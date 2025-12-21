import pyudev
import libwootility.hidraw


class Device:
    def __init__(self, parent):
        self.devices = []
        self.context = pyudev.Context()
        self.parent = pyudev.Devices.from_path(self.context, parent)
        self.open()

    def open(self):
        for udev in self.context.list_devices(parent=self.parent, subsystem="hidraw"):
            device_handle = open(udev.device_node, "wb+")
            self.devices.append(device_handle)
            hidraw = libwootility.hidraw.HIDRaw(device_handle)

            # fmt: off
            desc4 = [5, 1, 9, 6, 161, 1, 5, 8, 21, 0, 37, 1, 117, 1, 149, 5, 25, 1, 41, 5, 145, 2, 117, 3, 149, 1, 145, 1, 5, 7, 21, 0, 37, 1, 117, 1, 149, 8, 25, 224, 41, 231, 129, 2, 117, 1, 149, 46, 25, 4, 41, 49, 129, 2, 117, 2, 149, 1, 129, 1, 117, 1, 149, 105, 25, 51, 41, 155, 129, 2, 117, 7, 149, 1, 129, 1, 117, 1, 149, 8, 25, 157, 41, 164, 129, 2, 117, 1, 149, 46, 25, 176, 41, 221, 129, 2, 117, 2, 149, 1, 129, 1, 192]
            desc3 = [6, 85, 255, 9, 1, 161, 1, 133, 1, 9, 12, 21, 0, 38, 255, 0, 117, 8, 150, 32, 0, 129, 2, 9, 14, 145, 2, 9, 16, 149, 7, 177, 2, 133, 2, 9, 22, 150, 62, 0, 129, 2, 9, 24, 145, 2, 133, 3, 9, 32, 150, 254, 0, 129, 2, 9, 34, 145, 2, 133, 4, 9, 42, 150, 254, 1, 129, 2, 9, 44, 145, 2, 133, 5, 9, 52, 150, 254, 3, 129, 2, 9, 54, 145, 2, 133, 6, 9, 62, 150, 254, 7, 129, 2, 9, 64, 145, 2, 192]
            desc2 = [5, 1, 9, 128, 161, 1, 133, 1, 25, 129, 41, 131, 21, 1, 37, 3, 149, 1, 117, 8, 129, 0, 192, 5, 12, 9, 1, 161, 1, 133, 2, 25, 1, 42, 162, 2, 21, 1, 38, 162, 2, 149, 3, 117, 16, 129, 0, 192, 5, 1, 9, 2, 161, 1, 133, 3, 9, 1, 161, 0, 5, 9, 25, 1, 41, 5, 21, 0, 37, 1, 117, 1, 149, 5, 129, 2, 149, 3, 129, 3, 5, 1, 9, 48, 9, 49, 21, 129, 37, 127, 117, 8, 149, 2, 129, 6, 192, 192]
            desc1 = [6, 84, 255, 9, 1, 161, 1, 9, 2, 21, 0, 38, 255, 0, 117, 8, 149, 48, 129, 2, 192]
            # fmt: on

            if hidraw.getRawReportDescriptor() == desc3:
                # put control interface first
                self.devices[0], self.devices[-1] = self.devices[-1], self.devices[0]

    def close(self):
        for device in self.devices:
            device.close()
        self.devices = []

    def send_buffer(self, payload):
        device_handle = self.devices[0]
        for report, size in (2, 126), (3, 254), (4, 2044):
            if len(payload) < size:
                break
        buf = bytes((report, )) + payload + b"\x00" * (size - len(payload))
        device_handle.write(buf)
        device_handle.flush()

    def send_feature(self, payload):
        device_handle = self.devices[0]
        hidraw = libwootility.hidraw.HIDRaw(device_handle)
        hidraw.sendFeatureReport(payload)
        return device_handle.read(33)


def list_devices():
    context = pyudev.Context()
    for device in context.list_devices(DEVTYPE="usb_device"):
        if device.attributes.get("manufacturer") == b"Wooting":
            yield device


def get_device(parent):
    return Device(parent)
