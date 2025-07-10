#!/usr/bin/env python3
# LICENSE: BSD-3
# Author: Josh Pitts (@midnite_runr)

import os
import io
import sys
import struct
import shutil
import argparse


def gather_file_info(binary_path):
    """Parse the PE header of a Windows binary and extract relevant info."""
    with open(binary_path, 'rb') as binary:
        binary.seek(0x3C)
        pe_header_location = struct.unpack('<I', binary.read(4))[0]
        coff_start = pe_header_location + 4

        binary.seek(coff_start)
        machine_type = struct.unpack('<H', binary.read(2))[0]

        binary.seek(coff_start + 2)
        num_sections = struct.unpack('<H', binary.read(2))[0]
        timestamp = struct.unpack('<I', binary.read(4))[0]

        binary.seek(coff_start + 16)
        opt_hdr_size = struct.unpack('<H', binary.read(2))[0]
        characteristics = struct.unpack('<H', binary.read(2))[0]

        opt_hdr_start = coff_start + 20
        binary.seek(opt_hdr_start)
        magic = struct.unpack('<H', binary.read(2))[0]

        binary.seek(opt_hdr_start + 16)
        entry_point = struct.unpack('<I', binary.read(4))[0]
        patch_loc = entry_point

        binary.seek(opt_hdr_start + 24)
        image_base = struct.unpack('<Q' if magic == 0x20B else '<I', binary.read(8 if magic == 0x20B else 4))[0]

        binary.seek(opt_hdr_start + (56 if magic == 0x20B else 52))
        size_of_image_loc = binary.tell()
        size_of_image = struct.unpack('<I', binary.read(4))[0]

        binary.seek(opt_hdr_start + (88 if magic == 0x20B else 72))
        cert_table_loc = binary.tell()
        cert_loc = struct.unpack('<I', binary.read(4))[0]
        cert_size = struct.unpack('<I', binary.read(4))[0]

    return {
        'pe_header_location': pe_header_location,
        'coff_start': coff_start,
        'opt_hdr_start': opt_hdr_start,
        'magic': magic,
        'entry_point': entry_point,
        'patch_loc': patch_loc,
        'image_base': image_base,
        'size_of_image_loc': size_of_image_loc,
        'size_of_image': size_of_image,
        'cert_table_loc': cert_table_loc,
        'cert_loc': cert_loc,
        'cert_size': cert_size
    }


def copy_cert(exe_path):
    info = gather_file_info(exe_path)
    if info['cert_loc'] == 0 or info['cert_size'] == 0:
        return None
    with open(exe_path, 'rb') as f:
        f.seek(info['cert_loc'])
        return f.read(info['cert_size'])


def output_cert(exe_path, output_path):
    cert = copy_cert(exe_path)
    if cert and output_path:
        with open(output_path, 'wb') as out:
            out.write(cert)


def write_cert(cert, src_path, output_path):
    info = gather_file_info(src_path)
    shutil.copy2(src_path, output_path)
    with open(output_path, 'r+b') as f:
        with open(src_path, 'rb') as src:
            f.write(src.read())
        f.seek(info['cert_table_loc'])
        f.write(struct.pack("<I", os.path.getsize(src_path)))
        f.write(struct.pack("<I", len(cert)))
        f.seek(0, io.SEEK_END)
        f.write(cert)


def truncate_cert(exe_path, output_path):
    info = gather_file_info(exe_path)
    if info['cert_loc'] == 0 or info['cert_size'] == 0:
        print("Not signed.")
        sys.exit(1)

    shutil.copy2(exe_path, output_path)
    with open(output_path, 'r+b') as f:
        f.seek(-info['cert_size'], io.SEEK_END)
        f.truncate()
        f.seek(info['cert_table_loc'])
        f.write(b'\x00' * 8)


def sign_file(exe_path, sig_path, output_path):
    cert = open(sig_path, 'rb').read()
    info = gather_file_info(exe_path)
    shutil.copy2(exe_path, output_path)
    with open(output_path, 'r+b') as f:
        f.write(open(exe_path, 'rb').read())
        f.seek(info['cert_table_loc'])
        f.write(struct.pack("<I", os.path.getsize(exe_path)))
        f.write(struct.pack("<I", len(cert)))
        f.seek(0, io.SEEK_END)
        f.write(cert)


def check_signature(exe_path):
    info = gather_file_info(exe_path)
    if info['cert_loc'] == 0 or info['cert_size'] == 0:
        print("Unsigned.")
    else:
        print("Signed.")


def main():
    parser = argparse.ArgumentParser(description="PE Signature Tool")
    parser.add_argument("-i", "--input", help="Input file")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("-t", "--target", help="Target file to apply signature to")
    parser.add_argument("-s", "--sig", help="Signature file to add")
    parser.add_argument("-r", "--rip", action="store_true", help="Rip signature from input")
    parser.add_argument("-a", "--add", action="store_true", help="Add signature to target file")
    parser.add_argument("-c", "--check", action="store_true", help="Check if input file is signed")
    parser.add_argument("-T", "--truncate", action="store_true", help="Remove signature from input")

    args = parser.parse_args()

    if args.input and args.rip:
        output_cert(args.input, args.output or f"{args.input}_sig")

    elif args.input and args.target:
        cert = copy_cert(args.input)
        if cert:
            write_cert(cert, args.target, args.output or f"{args.target}_signed")

    elif args.check and args.input:
        check_signature(args.input)

    elif args.add and args.target and args.sig:
        sign_file(args.target, args.sig, args.output or f"{args.target}_signed")

    elif args.input and args.truncate:
        truncate_cert(args.input, args.output or f"{args.input}_nosig")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
