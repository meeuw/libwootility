"""
Test data sent from Wootility captured using Wireshark
"""
import struct
import libwootility.libwootility_report_pb2
import libwootility.libwootility_report


def test_decode_report():
    """
    Test decode report
    """
    report_data = bytes.fromhex(
        """
        d1 da 0e 00 4b 00 0a 17 0a 15 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a
        17 0a 15 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 0a 17 0a 15 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00
        """
    )
    assert report_data[:2] == libwootility.libwootility_report.D1DA
    assert report_data[2] == 0x0E  # RgbProfileColorsPart1
    libwootility_length = struct.unpack("!H", report_data[3:5])[0]
    assert libwootility_length > 0
    rgb_rows = libwootility.libwootility_report_pb2.RGBRows()
    rgb_rows.ParseFromString(report_data[6 : 6 + libwootility_length])
    for row in rgb_rows.payload:
        for i, key in enumerate(libwootility.helper.one_is_more_decode(row.row)):
            print(i, libwootility.helper.decode_color(key), end="")
        print()
    assert report_data[6 + libwootility_length :] == b"\x00" * 50
