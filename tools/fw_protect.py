#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
from pwn import *
import pathlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
from util import print_hex

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()

def protect_firmware(infile, outfile, version, message,secrets_path,debug):
    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        firmware = fp.read()
        
    firmware_blob = p16(version,endian='little') + p16(len(firmware),endian='little') + firmware + message.encode('ascii') + b'\x00'
    firmware_blob = bytes([b for b in firmware_blob for _ in range(2)])

    # open secrets file
    with open(secrets_path,'rb') as s:
      aes_key = base64.b64decode(s.read())

    iv = os.urandom(16)
    aes = AES.new(aes_key,AES.MODE_CBC,iv=iv)
    ct_bytes = aes.encrypt(pad(firmware_blob,AES.block_size))
    
    if debug:
      print("AES Key:")
      print_hex(aes_key)
      print("AES IV:")
      print_hex(iv)
      print("Ciphertext stub:")
      print_hex(ct_bytes[:128])
    
    encrypted_fw = iv + ct_bytes
    
    with open(outfile,'wb') as o:
      o.write(encrypted_fw)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True, type=int)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    parser.add_argument("--secrets", help = "Path to the secrets text file.", default = REPO_ROOT/"secret_build_output.txt")
    parser.add_argument("--debug",help = "Print debug info", action = "store_true")
    args = parser.parse_args()
    
    if len(args.message) > 255:
      print("Message must be 255 long at max")
      exit(1)
    if args.version > 65535 or args.version < 0:
      print("Version must fit in an unsigned short (0-65535)")
      exit(1)

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message,secrets_path=args.secrets,debug=args.debug)
    print("Produced encrypted firmware binary")
