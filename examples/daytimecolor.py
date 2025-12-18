import libwootility.libwootility_report
import libwootility.device_linux as libwootility_device
import time
import colorsys
import hsluv
import sys


def set_hue(hue):
    values = []
    rgb = colorsys.hls_to_rgb(hue, 0.5, 1)
    h = hsluv.rgb_to_hsluv(rgb)

    for i in range(21):
        if i < 10:
            c = hsluv.hsluv_to_rgb((h[0] + 0, h[1], h[2]))
        elif i < 12:
            c = hsluv.hsluv_to_rgb((h[0] + 10, h[1], h[2]))
        elif i < 14:
            c = hsluv.hsluv_to_rgb((h[0] + 20, h[1], h[2]))

        values.append(
            (int(c[0] * 255), int(c[1] * 255), int(c[2] * 255)),
        )

    payload = libwootility.libwootility_report.set_upper_rows_rgb(
        values, values, values
    )
    device.send_buffer(payload)

    payload = libwootility.libwootility_report.set_lower_rows_rgb(
        values, values, values
    )
    device.send_buffer(payload)


if __name__ == "__main__":
    device = libwootility_device.get_device(sys.argv[1])

    localtime = time.localtime()
    hue = (localtime.tm_hour * 60 + localtime.tm_min) / (24 * 60)
    # print(hue)
    # set_hue(12)
    set_hue(hue)
    # for i in range(0, 100):
    #    set_hue(i / 100)
