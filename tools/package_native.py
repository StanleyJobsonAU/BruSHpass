"""Package public native artifacts, source, notices and hashes; never credentials."""
from pathlib import Path
import hashlib
import json
import shutil
from zipfile import ZipFile, ZIP_DEFLATED

root = Path(__file__).resolve().parent.parent
dist = root / "dist" / "BruSHpass-release"
for filename in ("BruSHpass.exe", "BruSHpass", "templates/windows-x64.exe", "templates/linux-x64"):
    if not (dist / filename).is_file():
        raise FileNotFoundError(dist / filename)
for folder in ("docs", "native", "tools", "licenses", "assets"):
    (dist / folder).mkdir(exist_ok=True)
for obsolete in ("local-lab.md", "handshake-lab.md", "services.md", "protocol.md", "prototype-plan.md", "threat-model.md", "native-validation.md"):
    (dist / "docs" / obsolete).unlink(missing_ok=True)
for name in ("native.md",):
    shutil.copy2(root / "docs" / name, dist / "docs" / name)
shutil.copy2(root / "README.md", dist / "README.md")
shutil.copy2(root / "Protocol.md", dist / "Protocol.md")
shutil.copy2(root / "assets" / "brushpass-handshake.svg", dist / "assets" / "brushpass-handshake.svg")
for source in (root / "native").iterdir():
    if source.suffix in (".c", ".h", ".json"):
        shutil.copy2(source, dist / "native" / source.name)
shutil.copy2(root / "CMakeLists.txt", dist / "CMakeLists.txt")
for name in ("embed_templates.py", "build_native.ps1", "test_native.py"):
    shutil.copy2(root / "tools" / name, dist / "tools" / name)
for source, target in (
    (root / ".native-deps/openssl-linux/LICENSE.txt", "OpenSSL.txt"),
    (root / ".native-deps/zig-x86_64-windows-0.15.2/lib/libc/musl/COPYRIGHT", "musl.txt"),
    (root / ".native-deps/zig-x86_64-windows-0.15.2/LICENSE", "Zig.txt"),
):
    shutil.copy2(source, dist / "licenses" / target)
artifact_names = ["BruSHpass.exe", "BruSHpass", "templates/windows-x64.exe", "templates/linux-x64"]
manifest = {"tool": "BruSHpass", "protocol": "BrushPass", "version": "0.2.0", "dependencies": json.loads((root / "native/dependencies.json").read_text()),
            "sha256": {name: hashlib.sha256((dist / name).read_bytes()).hexdigest() for name in artifact_names}}
(dist / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
files = sorted(p for p in dist.rglob("*") if p.is_file() and p.suffix != ".zip")
assert not any(p.suffix in (".pem", ".key", ".sqlite") for p in files)
archive = dist / "BruSHpass-native.zip"
staged_archive = dist / "_BruSHpass-new.zip"
with ZipFile(staged_archive, "w", ZIP_DEFLATED) as bundle:
    for p in files:
        bundle.write(p, p.relative_to(dist).as_posix())
if archive.exists():
    archive.unlink()
staged_archive.rename(archive)
print(f"Packaged {len(files)} public files: {archive}")
