#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Updater Tool

A frame consists of two sections:
1. Two bytes for the length of the data section
2. A data section of length defined in the length section

[ 0x02 ]  [ variable ]
--------------------
| Length | Data... |
--------------------

In our case, the data is from one line of the Intel Hex formated .hex file

We write a frame to the bootloader, then wait for it to respond with an
OK message so we can write the next frame. The OK message in this case is
just a zero
"""

import argparse
from pwn import *
import time
import serial

from util import *

if platform.system() == 'Darwin':
    ser = serial.Serial("/dev/tty.usbmodem0E23AD551", 115200)
else:
    ser = serial.Serial("/dev/ttyACM0", 115200)

RESP_OK = b"\x00"
FRAME_SIZE = 256


def ready_bootloader():
    # Handshake for update
    ser.write(b"U")

    print("Waiting for bootloader to enter update mode...")
    while ser.read(1).decode() != "U":
        print("Got a non \'U\' byte")
    print("Bootloader is ready to update")


def send_frame(ser, frame, debug=False):
    ser.write(p16(len(frame),endian='little'))
  
    ser.write(frame)  # Write the frame...

    if debug:
        print_hex(frame)
    
    ser.flush()

    resp = ser.read(1)  # Wait for an OK from the bootloader

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    if debug:
        print("Resp: {}".format(ord(resp)))


def update(ser, infile, debug):
    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, "rb") as fp:
        firmware = fp.read()
    
    padding = (256-(len(firmware) % 256))
    firmware += p8(padding-1) * padding
    ready_bootloader()

    # Send firmware in frames
    num_frames = len(firmware) // FRAME_SIZE
    num_frames -= 1 if len(firmware) % FRAME_SIZE == 0 else 0
    for i in range(0, len(firmware), FRAME_SIZE):
        frame = firmware[i:i+FRAME_SIZE]
        send_frame(ser, frame, debug = debug)
        print(f"Sent frame {i // FRAME_SIZE} of {num_frames}")

    print("Done writing firmware.")

    # Send a zero length payload to tell the bootlader to finish writing it's page.
    ser.write(p16(0x0000, endian='little'))
    resp = ser.read(1)  # Wait for an OK from the bootloader
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded to zero length frame with {}".format(repr(resp)))
    print(f"Wrote zero length frame (2 bytes)")

    return ser


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")

    parser.add_argument("--port", help="Does nothing, included to adhere to command examples in rule doc", required=False)
    parser.add_argument("--firmware", help="Path to firmware image to load.", required=False)
    parser.add_argument("--debug", help="Enable debugging messages.", action="store_true")
    args = parser.parse_args()

    update(ser=ser, infile=args.firmware, debug=args.debug).close()
