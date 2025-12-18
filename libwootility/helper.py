"""
Helper functions for D1DA protocol
"""


def chunk_bytes(value, bit_length):
    """
    Chunk value into bytes of bit_length
    """
    for _ in range(0, value.bit_length(), bit_length):
        yield value & ((1 << bit_length) - 1)
        value >>= bit_length


def one_is_more_encode(values):
    """
    Encode value into bytes with 7 bits of payload and 1 bit
    which indicates the continuation.
    """
    result = bytearray()
    for value in values:
        if value == 0:
            result.append(0)
        else:
            first = True
            for byte in chunk_bytes(value, 7):
                if first:
                    first = False
                else:
                    result[-1] ^= 1 << 7
                result.append(byte)
    return bytes(result)


def one_is_more_decode(encoded):
    """
    Decode a byte sequence encoded with 7 bits of payload and 1 bit
    which indicates the continuation.
    """
    result = []
    current_value = 0
    shift = 0

    for byte in encoded:
        current_value |= (
            byte & 0x7F
        ) << shift  # Extract the lower 7 bits and shift them into place
        if byte & 0x80:  # If the 8th bit is set, continue to the next byte
            shift += 7
        else:  # If the 8th bit is not set, this is the last byte for the current value
            result.append(current_value)
            current_value = 0
            shift = 0

    return result


def encode_color(red, green, blue):
    """
    Encode RGB bytes into two bytes.
    """
    encode = 0
    encode |= (red & 0xF8) << 8
    encode |= (green & 0xFC) << 3
    encode |= (blue & 0xF8) >> 3
    return encode


def decode_color(encoded):
    """
    Decode two bytes into RGB bytes.
    """
    return (encoded >> 8) & 0xF8, (encoded >> 3) & 0xFC, (encoded << 3) & 0xF8


def ensure_size(values, size, default):
    if len(values) < size:
        values += (default,) * (size - len(values))
    if len(values) > size:
        values = values[:size]
    return values
