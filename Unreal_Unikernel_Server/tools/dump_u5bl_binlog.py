#!/usr/bin/env python3
"""Dump UE574 endpoint U5BL packet capture logs.

These .binlog files are NOT MSBuild Structured Log files.
They are raw UDP packet records emitted by ue574_endpoint --binlog.
"""
from __future__ import annotations
import argparse, datetime, ipaddress, struct, sys
from pathlib import Path

HDR = struct.Struct('<4sHBBQ4sH I')  # port is network order bytes read as LE-ish field; fixed below
# Easier: parse exact slices so IPv4/port stay network order.

def hex_ascii(data: bytes) -> str:
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off+16]
        hx = ' '.join(f'{b:02x}' for b in chunk)
        hx = hx + '   ' * (16 - len(chunk))
        asc = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        lines.append(f'  {off:04x}  {hx:<48} |{asc}|')
    return '\n'.join(lines)

def main() -> int:
    ap = argparse.ArgumentParser(description='Dump U5BL UE574 raw UDP .binlog packet captures')
    ap.add_argument('path')
    ap.add_argument('--summary', action='store_true')
    args = ap.parse_args()
    data = Path(args.path).read_bytes()
    off = 0
    rec = 0
    while off < len(data):
        if off + 26 > len(data):
            raise SystemExit(f'truncated header at offset {off}')
        magic = data[off:off+4]
        if magic != b'U5BL':
            raise SystemExit(f'bad magic at offset {off}; this is not a U5BL packet log')
        ver = int.from_bytes(data[off+4:off+6], 'little')
        direction = data[off+6]
        ts = int.from_bytes(data[off+8:off+16], 'little')
        ip = str(ipaddress.IPv4Address(data[off+16:off+20]))
        port = int.from_bytes(data[off+20:off+22], 'big')
        n = int.from_bytes(data[off+22:off+26], 'little')
        off += 26
        payload = data[off:off+n]
        if len(payload) != n:
            raise SystemExit(f'truncated payload at record {rec+1}')
        off += n
        rec += 1
        d = 'rx' if direction == 1 else 'tx' if direction == 2 else f'dir{direction}'
        when = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        print(f'#{rec} {d} {when} {ip}:{port} len={n}')
        if not args.summary:
            print(hex_ascii(payload))
    print(f'records={rec}')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
