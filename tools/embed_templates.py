"""Build-time only: convert native executable templates into C data arrays."""
from pathlib import Path
import sys

windows, linux, output = map(Path, sys.argv[1:])
with output.open("w", encoding="ascii") as f:
    f.write("#include <stddef.h>\n")
    for name, path in (("windows", windows), ("linux", linux)):
        data = path.read_bytes()
        if name == "windows" and data[:2] != b"MZ":
            raise ValueError("Windows template is not PE")
        if name == "linux" and data[:4] != b"\x7fELF":
            raise ValueError("Linux template is not ELF")
        f.write(f"const unsigned char bp_template_{name}[] = {{\n")
        for pos in range(0, len(data), 32):
            f.write(",".join(f"0x{b:02x}" for b in data[pos:pos+32]) + ",\n")
        f.write(f"}};\nconst size_t bp_template_{name}_size = sizeof(bp_template_{name});\n")
