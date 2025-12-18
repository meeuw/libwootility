"""
Tests for libwootility.helper functions
"""
import pytest
import libwootility.helper


@pytest.mark.parametrize(
    "test_input,expected",
    [
        ("1111 1000 0000 0000", "1000 0000 1111 0000 0000 0011"),  # Red
        ("      111 1110 0000", "          1110 0000 0000 1111"),  # Green
        ("             1 1111", "                       1 1111"),  # Blue
        ("1111 1111 1111 1111", "1111 1111 1111 1111 0000 0011"),  # White
        ("0", "0"),  # Black
    ],
)
def test_one_is_more_encode(test_input, expected):
    """
    Test libwootility.helper.one_is_more_encode
    """
    actual = libwootility.helper.one_is_more_encode(
        (int(test_input.replace(" ", ""), 2),)
    )
    assert bin(int(actual.hex(), 16)) == f"0b{expected.replace(' ', '')}"


@pytest.mark.parametrize(
    "test_input,expected",
    [
        ((0xFF, 0x00, 0x00), "1111100000000000"),  # Red
        ((0x00, 0xFF, 0x00), "     11111100000"),  # Green
        ((0x00, 0x00, 0xFF), "           11111"),  # Blue
        ((0xFF, 0xFF, 0xFF), "1111111111111111"),  # White
    ],
)
def test_encode_color(test_input, expected):
    """
    Test libwootility.helper.encode_color
    """
    actual = libwootility.helper.encode_color(*test_input)
    assert bin(actual) == f"0b{expected.replace(' ', '')}"


@pytest.mark.parametrize(
    "rgb",
    [
        (0xF8, 0x00, 0x00),
        (0x00, 0xF8, 0x00),
        (0x00, 0x00, 0xF8),
    ],
)
def test_encode_decode_color(rgb):
    """
    Test libwootility.helper.decode_color
    """
    assert (
        libwootility.helper.decode_color(libwootility.helper.encode_color(*rgb)) == rgb
    )
