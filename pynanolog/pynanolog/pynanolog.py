import collections
import pathlib
import json
import struct
import sys


def varint_decode(payload, idx):
    val = 0

    while True:
        next_byte = payload[idx]
        idx += 1
        val = (val << 7) + (next_byte & 0x7F)
        if not (next_byte & 0x80):
            break

    return val, idx


def varint_encode(x):
    enc = bytearray()
    while True:
        enc.append((x & 0xFF) | 0x80)
        if (x := x >> 7) == 0:
            break
    enc.reverse()
    enc[-1] &= 0x7F
    return enc


def zigzag_decode(x):
    return (x >> 1) ^ -(x & 1)


def zigzag_encode(x):
    return (x >> 31) ^ (x << 1)


def load_json_manifest(filename):
    return json.loads(pathlib.Path(filename).read_text())


LogString = collections.namedtuple('LogString', ['severity', 'text'])


def format_str(json_manifest, binary_payload):
    guid, idx = varint_decode(binary_payload, 0)

    if guid > len(json_manifest):
        raise ValueError(f'Guid {guid} is larger than json manifest')

    entry = json_manifest[guid]

    # TODO: memoize the extraction per-guid the first time it's encountered
    fields = []
    for spec in entry.get('format_specifiers', []):
        if spec.get('field-width', None) == 'dynamic':
            fw, idx = varint_decode(binary_payload, idx)
            fields.append(zigzag_decode(fw))

        if spec.get('precision', None) == 'dynamic':
            prec, idx = varint_decode(binary_payload, idx)
            fields.append(zigzag_decode(prec))

        scalar_size = 4
        if len_spec := spec.get('length', None):
            if len_spec == 'char':
                scalar_size = 1
            elif len_spec == 'short':
                scalar_size = 2
            elif len_spec == 'long':
                scalar_size = 4
            elif len_spec == 'large':
                scalar_size = 8
            elif len_spec == 'long-double':
                scalar_size = 8
            else:
                raise ValueError(f'Unknown manifest length "{len_spec}" (guid {guid})')

        type_str = spec['type']
        if type_str == 'char':
            fields.append(struct.unpack('c', binary_payload[idx:idx + 1])[0])
            idx += 1
        elif type_str == 'pointer':
            fields.append(struct.unpack('<L', binary_payload[idx:idx + 4])[0])
            idx += 4
        elif type_str == 'string':
            str_len, idx = varint_decode(binary_payload, idx)
            fields.append(struct.unpack(
                f'{str_len}s', binary_payload[idx:idx + str_len])[0].decode())
            idx += str_len
        elif type_str == 'int':
            unpack_type = {1: 'b', 2: 'h', 4: 'i', 8: 'q'}[scalar_size]
            fields.append(struct.unpack(f'<{unpack_type}',
                          binary_payload[idx:idx + scalar_size])[0])
            idx += scalar_size
        elif type_str == 'binary' or \
                type_str == 'octal' or \
                type_str == 'hex' or \
                type_str == 'unsigned':
            unpack_type = {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}[scalar_size]
            fields.append(struct.unpack(f'<{unpack_type}',
                          binary_payload[idx:idx + scalar_size])[0])
            idx += scalar_size
        elif type_str == 'float-decimal' or \
                type_str == 'float-scientific' or \
                type_str == 'float-shortest' or \
                type_str == 'float-hex':
            unpack_type = {4: 'f', 8: 'd'}[scalar_size]
            fields.append(struct.unpack(f'<{unpack_type}',
                          binary_payload[idx:idx + scalar_size])[0])
            idx += 4
        else:
            raise ValueError(f'Unknown manifest type "{type_str}" (guid {guid})')

    return LogString(entry['severity'], entry['python'].format(*fields)), idx


if __name__ == '__main__':
    print(sys.argv)
    json_manifest = load_json_manifest(sys.argv[1])

    payload = bytearray()
    payload.append(5)  # GUID
    payload.extend(varint_encode(11))  # string length
    payload.extend('hello world'.encode())  # string body
    print(format_str(json_manifest, payload)[0])

    print(format_str(json_manifest, struct.pack('<Bii', 27, 12345, 54321))[0])
