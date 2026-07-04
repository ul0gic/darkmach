#!/usr/bin/env python3
"""
Generate a replacement main() for an iOS app by compiling a minimal
stub as a fully-linked executable, then extracting the _main bytes.

Because the stub is position-independent and links against the same
frameworks, the dynamic linker resolves everything at load time.
"""

import struct
import subprocess
import sys
import tempfile
from pathlib import Path


def make_stub(app_delegate_class, output_path, cryptoff=0, target_size=4096):
    """
    Compile a full simulator executable with a replacement main(),
    extract the _main function bytes, and write them padded to target_size.
    """

    source = f"""
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

int main(int argc, char *argv[]) {{
    @autoreleasepool {{
        Class cls = objc_getClass("{app_delegate_class}");
        NSString *clsName = cls ? NSStringFromClass(cls) : nil;
        return UIApplicationMain(argc, argv, nil, clsName);
    }}
}}
"""

    sdk_path = (
        subprocess.check_output(["xcrun", "--sdk", "iphonesimulator", "--show-sdk-path"])
        .decode()
        .strip()
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = Path(tmpdir) / "main.m"
        bin_path = Path(tmpdir) / "main_stub"

        with src_path.open("w") as f:
            f.write(source)

        result = subprocess.run(
            [
                "clang",
                "-arch",
                "arm64",
                "-target",
                "arm64-apple-ios17.0-simulator",
                "-isysroot",
                sdk_path,
                "-framework",
                "UIKit",
                "-framework",
                "Foundation",
                "-lobjc",
                "-O2",
                "-o",
                bin_path,
                src_path,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            print(f"Compilation failed:\n{result.stderr}")
            return None

        otool_out = subprocess.check_output(["otool", "-l", bin_path], text=True)

        entryoff = None
        text_offset = None
        text_size = None
        lines = otool_out.split("\n")
        for i, line in enumerate(lines):
            if "LC_MAIN" in line:
                for j in range(i, min(i + 5, len(lines))):
                    if "entryoff" in lines[j]:
                        entryoff = int(lines[j].split()[-1])
                        break
            if "__text" in line and "__TEXT" in line:
                for j in range(i, min(i + 8, len(lines))):
                    if "offset" in lines[j] and "sectname" not in lines[j]:
                        text_offset = int(lines[j].split()[-1])
                    if "size" in lines[j] and "sectname" not in lines[j]:
                        val = lines[j].split()[-1]
                        text_size = int(val, 16) if val.startswith("0x") else int(val)

        print(
            f"Stub binary: entryoff=0x{entryoff:x}, "
            f"__text offset=0x{text_offset:x}, __text size=0x{text_size:x}"
        )

        result = subprocess.run(
            ["otool", "-tv", bin_path], capture_output=True, text=True, check=False
        )
        print(f"\nDisassembly:\n{result.stdout[:2000]}")

        with bin_path.open("rb") as f:
            f.seek(text_offset)
            text_bytes = f.read(text_size)

        print(f"\n__text section: {len(text_bytes)} bytes")

        main_offset_in_text = entryoff - text_offset
        print(f"_main at offset {main_offset_in_text} within __text")

        main_bytes = text_bytes[main_offset_in_text:]
        print(f"_main code: {len(main_bytes)} bytes")

        if len(main_bytes) > target_size:
            print(f"WARNING: code ({len(main_bytes)} bytes) > target ({target_size} bytes)")

        # 0xD503201F = NOP, 0xD4200000 = BRK
        nop = struct.pack("<I", 0xD503201F)
        brk = struct.pack("<I", 0xD4200000)

        region = bytearray()
        pre_main_size = 0x90  # entry point is at +0x90 within encrypted region
        while len(region) < pre_main_size:
            region += nop
        region += main_bytes
        while len(region) < target_size:
            region += brk

        with Path(output_path).open("wb") as f:
            f.write(region[:target_size])

        print(f"\nReplacement region: {target_size} bytes")
        print(f"  NOPs: 0x000 - 0x{pre_main_size - 1:03x}")
        print(f"  main: 0x{pre_main_size:03x} - 0x{pre_main_size + len(main_bytes) - 1:03x}")
        print(f"  BRK:  0x{pre_main_size + len(main_bytes):03x} - 0x{target_size - 1:03x}")
        print(f"\nWritten to {output_path}")

        return region[:target_size]


if __name__ == "__main__":
    delegate = sys.argv[1] if len(sys.argv) > 1 else "_TtC11AccuWeather11AppDelegate"
    output = sys.argv[2] if len(sys.argv) > 2 else "/tmp/main_stub.bin"
    make_stub(delegate, output)
