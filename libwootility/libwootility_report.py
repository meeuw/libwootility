import struct
import libwootility.libwootility_report_pb2
from libwootility.helper import encode_color, one_is_more_encode, ensure_size

D1DA = b"\xd1\xda"


def set_upper_rows_rgb(row1, row2, row3):
    """
    Set the upper three rows of RGB leds.

    Rows are an iterable of rgb values
    """
    row1 = ensure_size(row1, 21, (0, 0, 0))
    row2 = ensure_size(row2, 21, (0, 0, 0))
    row3 = ensure_size(row3, 21, (0, 0, 0))

    rgb_rows_pb2 = libwootility.libwootility_report_pb2.RGBRows()
    rgb_rows_pb2.payload.add(row=one_is_more_encode(encode_color(*rgb) for rgb in row1))
    rgb_rows_pb2.payload.add(row=one_is_more_encode(encode_color(*rgb) for rgb in row2))
    rgb_rows_pb2.payload.add(row=one_is_more_encode(encode_color(*rgb) for rgb in row3))
    return (
        D1DA
        + b"\x0e"  # RgbProfileColorsPart1
        + struct.pack("!H", rgb_rows_pb2.ByteSize())
        + b"\x00"
        + rgb_rows_pb2.SerializeToString()
    )


def set_lower_rows_rgb(row1, row2, row3):
    """
    Set the upper three rows of RGB leds.

    Rows are an iterable of rgb values
    """
    row1 = ensure_size(row1, 21, (0, 0, 0))
    row2 = ensure_size(row2, 21, (0, 0, 0))
    row3 = ensure_size(row3, 21, (0, 0, 0))

    rgb_rows_pb2 = libwootility.libwootility_report_pb2.RGBRows()
    rgb_rows_pb2.payload.add(row=one_is_more_encode(encode_color(*rgb) for rgb in row1))
    rgb_rows_pb2.payload.add(row=one_is_more_encode(encode_color(*rgb) for rgb in row2))
    rgb_rows_pb2.payload.add(row=one_is_more_encode(encode_color(*rgb) for rgb in row3))
    return (
        D1DA
        + b"\x0f"  # RgbProfileColorsPart2
        + struct.pack("!H", rgb_rows_pb2.ByteSize())
        + b"\x00"
        + rgb_rows_pb2.SerializeToString()
    )


def set_brightness(brightness, a=0xFFFF, b=0xFFFF, c=0xFFFF, d=0xFFFF):
    """
    Set brightness
    """
    brightness_pb2 = libwootility.libwootility_report_pb2.Brightness(
        payload={
            "brightness": brightness,
            "a": a,
            "b": b,
            "c": c,
            "d": d,
        }
    )
    return (
        D1DA
        + b"\x16"  # RgbProfileCore
        + struct.pack("!H", brightness_pb2.ByteSize())
        + brightness_pb2.SerializeToString()
    )


def rgb_array_update_keyboard(*args):
    """
    Update RGB array of keyboard.

    args should be encoded as:

    encode |= (red & 0xf8) << 8;
    encode |= (green & 0xfc) << 3;
    encode |= (blue & 0xf8) >> 3;

    This is only supported after calling woot_dev_init.
    """
    array = b"".join((struct.pack("H", encode_color(*rgb)) for rgb in args))
    return D1DA + b"\x0b" + array  # WootDevRawReport


def keymap():
    """
    d0 da 14 01 02 00 00 96 0a 17 0a 15 ff ff ff ff
    ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
    ff 0a 17 0a 15 32 37 38 39 3a 3b 3c 3d 3e 3f 40
    41 42 49 ff ff ff ff ff ff ff 0a 17 0a 15 c3 c5

    c4 c1 c2 c0 ff ff 4f 44 43 48 47 ff ff ff ff ff
    ff ff ff 0a 17 0a 15 36 ff ff ff ff e1 e0 4d 4e
    4c 4b 4a ff e6 ff ff ff ff ff ff ff 0a 17 0a 15
    64 ff ff ff ff ff ff ff ff d2 45 46 ff 68 ff ff

    ff ff ff ff ff 0a 17 0a 15 63 66 65 ff ff ff ff
    ff ff ff 69 ea 77 67 ff ff ff ff ff ff ff 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    """
    return D1DA + b"\x14"  # MappingProfile


def rgb_power_off(dim_minutes, off_minutes):
    """
    enable:
    d0 da 17 00 08 0a 04 08 05 10 0a 10

    disable:
    d0 da 17 00 02 10
    """
    # GlobalSettings
