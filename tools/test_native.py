"""Exercise the real native server/exporter and exported Windows clients.

Uses temporary loopback listeners and synthetic commands; never the LAN service.
"""
import argparse
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import threading
import time


class Process:
    def __init__(self, args, cwd):
        self.text = ""
        self.lock = threading.Lock()
        self.process = subprocess.Popen(args, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
        def read():
            for c in iter(lambda: self.process.stdout.read(1), ""):
                with self.lock:
                    self.text += c
        self.thread = threading.Thread(target=read, daemon=True)
        self.thread.start()

    def send(self, command):
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()

    def wait(self, pattern, timeout=25, start=0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                found = re.search(pattern, self.text[start:])
                snapshot = self.text
            if found:
                return found
            if self.process.poll() is not None:
                break
            time.sleep(0.05)
        raise AssertionError(f"Missing {pattern!r}; exit={self.process.poll()}; output:\n{snapshot[-8000:]}")

    def close(self, gracefully=False):
        if self.process.poll() is None:
            if gracefully:
                self.send("quit")
                try:
                    self.process.wait(timeout=22)
                except subprocess.TimeoutExpired:
                    self.process.terminate()
            else:
                self.process.terminate()
            self.process.wait(timeout=5)
        self.thread.join(timeout=2)
        self.process.stdin.close()
        self.process.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, default=Path("build/windows-server/Release/BruSHpass.exe"))
    args = parser.parse_args()
    binary = args.server.resolve()
    windows = os.name == "nt"
    target = "windows-x64" if windows else "linux-x64"
    other_target = "linux-x64" if windows else "windows-x64"
    suffix = ".exe" if windows else ""
    subprocess.run([str(binary), "--self-test"], check=True)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="brushpass-native-") as temp:
        root = Path(temp)
        (root / "subdir").mkdir()
        server = Process([str(binary), "-i", "127.0.0.1", "-p", str(port)], root)
        clients = []
        try:
            server.wait("BruSHpass native server")
            identities = []
            for i in (1, 2):
                filename = f"agent{i}{suffix}"
                server.send(f"export-client {target} {filename}")
                match = server.wait(rf"Exported client ([a-f0-9]{{32}}) to {re.escape(filename)}")
                identities.append(match[1])
                client = Process([str(root / filename)], root)
                clients.append(client)
                client.wait("Authenticated session established")
                server.wait(rf"session established\] client={match[1]}")
            assert identities[0] != identities[1]
            server.send(f"export-client {other_target} other-agent")
            server.wait("to other-agent")
            assert (root / "other-agent").read_bytes().startswith(b"\x7fELF" if windows else b"MZ")
            server.send(f"export-client {target} agent1{suffix}")
            server.wait("Client export failed")

            def command(client_id, text, expected, timeout=25):
                start = len(server.text)
                server.send(f"send {client_id} {text}")
                server.wait(expected, timeout=timeout, start=start)
                server.wait(rf"{client_id} command=\d+ complete exit=0", timeout=timeout, start=start)

            command(identities[0], "echo BRUSHPASS_NATIVE_OK", "BRUSHPASS_NATIVE_OK")
            command(identities[1], "echo SECOND_CLIENT_OK", "SECOND_CLIENT_OK")
            command(identities[0], "cd subdir", "subdir")
            command(identities[0], "cd", "subdir")
            command(identities[1], "cd", re.escape(str(root)))
            chunk_command = ('for /L %i in (1,1,200) do @echo CHUNK_LINE' if windows else
                             'i=0; while [ "$i" -lt 200 ]; do echo CHUNK_LINE; i=$((i+1)); done')
            command(identities[0], chunk_command, r"chunk=[1-9]", timeout=35)
            # Queued commands execute in order, after prior output is completed.
            start = len(server.text)
            server.send(f"send {identities[0]} echo QUEUED_A")
            server.send(f"send {identities[0]} echo QUEUED_B")
            server.wait("QUEUED_A", start=start)
            server.wait("QUEUED_B", start=start)
            assert server.text[start:].index("QUEUED_A") < server.text[start:].index("QUEUED_B")

            start = len(server.text)
            large_output = ('for /L %i in (1,1,3000) do @echo LIMIT_LINE' if windows else
                            'i=0; while [ "$i" -lt 3000 ]; do echo LIMIT_LINE; i=$((i+1)); done')
            server.send(f"send {identities[0]} {large_output}")
            server.wait(rf"{identities[0]} command=\d+ complete exit=125", timeout=40, start=start)
            start = len(server.text)
            timeout_command = 'ping -n 30 127.0.0.1 >nul' if windows else 'sleep 30'
            server.send(f"send {identities[0]} {timeout_command}")
            server.wait(rf"{identities[0]} command=\d+ complete exit=124", timeout=25, start=start)

            start = len(server.text)
            server.send(f"drop {identities[0]}")
            server.wait("Session discarded", start=start)
            server.wait(rf"session established\] client={identities[0]}", start=start)
            # Fresh logical session restores the initial directory.
            command(identities[0], "cd", re.escape(str(root)))
            # No state databases, histories, or automatic log files.
            assert {p.name for p in root.iterdir()} == {"subdir", "brushpass-identity.pem", f"agent1{suffix}", f"agent2{suffix}", "other-agent"}
            for client in clients:
                client.close()
            clients = []
            server.close(gracefully=True)
            credential = (root / "brushpass-identity.pem").read_bytes()
            server = Process([str(binary), "-i", "127.0.0.1", "-p", str(port)], root)
            server.wait("BruSHpass native server")
            assert (root / "brushpass-identity.pem").read_bytes() == credential
            client = Process([str(root / f"agent1{suffix}")], root)
            clients.append(client)
            client.wait("Authenticated session established")
            print("Native integration passed: exports, unique clients, commands, cwd, chunking, ordered queues, fresh sessions, retained identity, no message files.")
        finally:
            for client in clients:
                client.close()
            server.close(gracefully=True)


if __name__ == "__main__":
    main()
