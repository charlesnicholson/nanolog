import argparse
import json
import pathlib
import struct
import sys

def _parse_args():
  parser = argparse.ArgumentParser()
  parser.add_argument('-i', '--input-file', required=True, type=pathlib.Path)

  args = parser.parse_args()
  if not args.input_file.exists():
    raise ValueError(f'Input file {args.input_file} not found, aborting')

  return args

def decode_varint(payload):
  val, idx = 0, 0
  for idx, cur_byte in enumerate(payload):
    val = val | ((cur_byte & 0x7f) << (7 * idx))
    if (cur_byte & 0x80) == 0:
      break

  return idx + 1, val


def main():
  args = _parse_args()
  manifest = json.loads(args.input_file.read_text())
  print(len(manifest))

  payload = struct.pack('=BBB5siB6s', 0xF2, 0x06, 5, 'Hello'.encode(), 1234567, 6, 'Doggos'.encode())

  print(payload)
  vi_len, guid = decode_varint(b'\xF2\x06')
  payload = payload[vi_len:]
  print(payload)

  format_str = manifest[guid]['python_format']
  pack = ['Hello', 1234567, 'Doggos']
  print(format_str.format(*pack))
  return 0

if __name__ == '__main__':
  sys.exit(main())
