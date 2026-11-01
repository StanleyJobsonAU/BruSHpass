# BruSHpass native C tool: BrushPass protocol version 2

BruSHpass is the remote administration implementation of the BrushPass protocol. The current native deliverables are `dist/BruSHpass-release/BruSHpass.exe` for Windows x64 and `dist/BruSHpass-release/BruSHpass` for Linux x64. Each server contains both client executable templates. A server can export uniquely provisioned clients for either operating system without a compiler, Python, OpenSSL DLLs, or sidecar templates at runtime. The supplied Linux binary is statically linked with musl and OpenSSL; the Windows binary uses static OpenSSL and the static MSVC runtime with Windows system DLLs.

Nothing is installed or started automatically by these binaries. Clients run visibly as the account that launches them, initiate outbound connections, and execute commands under that account's permissions. There is no elevation or service installation.

## Start the server and export clients

Windows, from a writable working directory:

```powershell
.\BruSHpass.exe -i 192.0.2.10 -p 8443
```

An interface friendly name such as `-i Ethernet` is also accepted. On Linux:

```bash
chmod +x BruSHpass
./BruSHpass -i eth0 -p 8443
```

Both forms resolve one IPv4 address from the specified interface; IPv6 and non-x64 targets are outside this first implementation. Binding defaults to `127.0.0.1:8443`. The listener uses the selected interface address, not a packet capture interface.

At the server prompt:

```text
export-client linux-x64 linux-client 192.0.2.10
export-client windows-x64 windows-client.exe 192.0.2.10
```

The advertised host defaults to the bound address; provide it explicitly if the client reaches the server through another address. Binding `0.0.0.0` requires an explicit advertised host. Output paths may be quoted. Export refuses to overwrite existing files. Each export creates a new random client ID, EC private key, and client certificate signed by this server's private CA. The resulting executable embeds its endpoint, identity, CA certificate, and exact server certificate fingerprint. It contains no server private key. Treat exported executables as private credentials; use a separate export per client machine.

Transfer the appropriate executable through your trusted local channel. On Linux:

```bash
chmod 700 linux-client
./linux-client
```

On Windows, run `windows-client.exe`. No command-line configuration or state directory is needed. The client prints its ID and endpoint, establishes an authenticated session, and polls. Ctrl+C stops the client. Configure the firewall to allow the server executable and selected TCP port.

## Operator console

```text
clients
use <32-character-client-id>
echo Hello
cd /tmp
pwd
```

For a Windows client, use Windows command syntax, for example `cd C:\Windows` and `dir`. `cd` is an agent builtin that updates the session working directory and prints it; `cd` without an argument prints the current directory on both platforms. Other commands run through `/bin/sh -c` on Linux or `cmd.exe /D /S /C` on Windows. They are non-interactive subprocesses, not a terminal/PTY. Input is disconnected, and stdout/stderr are combined.

To address a client without selecting it:

```text
send <client-id> echo Hello
drop <client-id>
help
quit
```

Commands are limited to 512 bytes, with up to 64 queued frames per client and 32 connected identities. Commands for a client run in order; the next command is released after completion of the previous command. Other clients have independent queues and working directories. `help`, `clients`, `use`, `drop`, `export-client`, `quit`, and `exit` are local console commands; use `send` when a remote command conflicts with one of these names.

Output is capped at 16 KiB per command, split into 512-byte chunks. Completion reports the command ID and exit status. Wrapper statuses are 124 for timeout, 125 for truncated output, and 126 for execution setup failure. Execution is limited to 15 seconds; Windows uses a kill-on-close job object, while Linux terminates the child process group. Output controls are escaped before display to avoid passing terminal escape sequences through from a client.

Idle polling is once per second; pending output drains at 100 ms intervals. Each output frame is retained in RAM until acknowledged, with duplicate detection inside that session. This is an experimental, bounded command runner, not an interactive terminal or bulk-transfer protocol.

## Ephemeral sessions and retained identity

No message database, inbox history, command log, or session counter file is created. Both ends keep message queues, acknowledgment state, keys, counters, and duplicate tracking in memory. Output is displayed on the console; redirection or terminal logging remains under the operator's control.

An abnormal exchange causes the client to discard session keys and pending results, restore its initial working directory, and reconnect with a new session. A successfully completed TLS connection closes normally between exchanges and does not discard the logical session. The server replaces old session state only after an authenticated fresh setup, or expires it after 60 seconds without an accepted exchange. An unauthenticated connection claiming another client's ID cannot delete that client's session.

`drop` discards a connected client's in-memory session and queues. That client establishes a new session on its next successful reconnect. A command that executed before a disconnect can have an unknown outcome; discarded commands are never automatically replayed into a new session. Filesystem or other external effects already performed by a command are not undone.

The server creates **one retained identity credential**, `brushpass-identity.pem`, so previously exported clients still trust it after a restart. Override the path with `--identity <path>`. The file contains the CA and server private keys/certificates, not message state. It is currently an **unencrypted PEM protected by owner/SYSTEM permissions on Windows or mode 0600 on Linux**. Exported client private keys are embedded in their binaries and can be extracted by someone possessing those binaries. No OS credential vault or passphrase encryption has been implemented in this native milestone. Do not copy or publish these credentials.

Deleting/replacing the identity changes server trust and requires fresh client exports. The certificates last one year. Individual persistent revocation, automatic renewal, and secret-vault integration are not implemented. Do not run multiple copies of the same exported identity: an authenticated fresh setup replaces its prior session.

## Key establishment and wire protocol

The native protocol uses wire version 2. Sensitive messages are never placed in the first ClientHello of a session:

1. ClientHello carries a public client ID and random setup nonce in extension `0xff02`.
2. EncryptedExtensions returns a fresh random session ID and the echoed nonce. This exchange contains no commands or output.
3. After certificate validation and a full TLS 1.3/mTLS handshake, each side calls the [OpenSSL TLS exporter API](https://docs.openssl.org/3.6/man3/SSL_export_keying_material/). The label is `EXPORTER-BrushPass-v2`, and the context is `client_id || client_nonce || session_id`. The 64-byte result supplies separate 32-byte request and response keys.
4. Later fresh TLS handshakes carry AES-256-GCM-encrypted frames in the ClientHello and negotiated EncryptedExtensions. Each direction has its own key and a strictly increasing transmission counter. The 96-bit nonce is four zero bytes followed by the big-endian transmission counter. A cached ClientHello extension is reused unchanged for HelloRetryRequest.
5. Received frames are staged during extension parsing and committed only after successful peer authentication. The server's response acknowledges previously accepted frames, never acceptance of the current request before client authentication. The client additionally requires successful TLS shutdown before accepting a response.

Every physical connection authenticates certificates; resumption, tickets, early data, and protocol fallback are disabled. The server verifies its own CA's client chain and binds the certificate CN to the claimed client ID. A client validates the CA chain and exact pinned server certificate. Server identity is pinned rather than inferred from the endpoint hostname. No `SSL_write` application-data transport is used. 

All integers below are big-endian. The outer extension header is 47 bytes:

| Field | Bytes |
| --- | ---: |
| Magic `BP2\0` | 4 |
| Type: OPEN=1, OPEN_REPLY=2, DATA=3 | 1 |
| Client ID | 16 |
| Session ID (zero in OPEN) | 16 |
| Transmission counter (zero in setup) | 8 |
| Following data length | 2 |

Setup contains a 16-byte client nonce. DATA contains an encrypted frame and a 16-byte GCM tag; the entire outer header is authenticated as AAD. The inner frame has a 31-byte header: frame ID (8), acknowledgment (8), command ID (8), chunk index (4), kind (1), body length (2), then 0–512 body bytes. Kind 0 is an empty poll with frame ID 0; kinds 1/2/3 are command/output/completion. Completion has a four-byte exit status. Queued frame IDs are separate from transmission counters: retries retain their frame ID but get a new transmission counter/nonce. Duplicate frame content must match, excluding updated acknowledgment metadata.

Both the extension number and visible magic identify this experimental protocol. It makes no claim of traffic indistinguishability. A packet capture sees the setup metadata and encrypted client envelope; the server's extension is also protected by TLS handshake encryption. TLS record labels can still say Application Data while carrying encrypted handshake records.

## Building and validation

This workspace's cross-build command is:

```powershell
.\tools\build_native.ps1
```

It expects Visual Studio 2022 C tools, vcpkg with `openssl:x64-windows-static`, Zig 0.15.2, and Linux/musl OpenSSL archives in `.native-deps`. It rebuilds both templates first, embeds both into both server builds, and copies final binaries to `dist`. Python is used for build-time embedding and integration tests only. See [native build dependencies](../native/dependencies.json) for the versions used here. The `.native-deps` cache is deliberately excluded from version control.

On a Linux build machine with CMake, a C compiler, Python 3 for embedding, and OpenSSL development files, first build a template:

```bash
cmake -S . -B build/linux-template -DCMAKE_BUILD_TYPE=Release -DBP_CLIENT_TEMPLATE=ON
cmake --build build/linux-template -j4
```

Then supply that template and a Windows template when configuring the final server:

```bash
cmake -S . -B build/linux-server -DCMAKE_BUILD_TYPE=Release \
  -DBP_TEMPLATE_LINUX="$PWD/build/linux-template/BruSHpass" \
  -DBP_TEMPLATE_WINDOWS=/path/to/windows-template.exe
cmake --build build/linux-server -j4
```

The supplied release includes a `templates/` directory for rebuilding; it is not required to run either final server binary. Normal system builds may retain a libc dependency; the shipped Linux artifact specifically uses static musl to avoid that dependency. Static OpenSSL is requested by default. OpenSSL must be version 3.0 or later; the supplied binaries use 3.6.5.

Validation commands:

```powershell
.\dist\BruSHpass-release\BruSHpass.exe --self-test
.\.venv\Scripts\python.exe tools/test_native.py --server dist/BruSHpass-release/BruSHpass.exe
```

The C self-test checks encryption, tag tampering, replay, deduplication, and acknowledgments. The real Windows integration test covers native exports for both formats, distinct clients, command execution, session working directories, chunked output, ordered command queues, session replacement, retained identity across restart, and the absence of message files. Linux server and agent binaries are cross-compiled here; Linux runtime validation is still required on the target Linux system. On Linux, the integration harness can use `python3 tools/test_native.py --server ./BruSHpass` with the native server path.

The listener currently processes handshakes sequentially, so slow peers can delay others. There is a ten-second TLS-operation deadline, but no production admission control, per-client revocation registry, PTY, or comprehensive protocol audit. The implementation has not undergone an independent security audit. OpenSSL licensing and musl notices accompany the binaries.
