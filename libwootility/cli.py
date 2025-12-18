import click
import libwootility.device_linux as libwootility_device
import libwootility.helper
import libwootility.libwootility_feature
import libwootility.libwootility_report


@click.group()
def main():
    pass


@main.command()
def list_devices():
    for device in libwootility_device.list_devices():
        click.echo(device)


@main.command()
@click.option("--device", required=True)
@click.option("--report", required=True)
@click.option("--value", required=True, multiple=True)
def libwootility_report(device, report, value):
    device = libwootility_device.get_device(device)

    pass_values = []
    for val in value:
        if val.startswith("rgb:"):
            pass_values.append(
                (int(val[4:6], 16), int(val[6:8], 16), int(val[8:10], 16))
            )
        elif val.startswith("rgbrow:"):
            row = []
            for rgbrow in val[7:].split(","):
                row.append(
                    (
                        int(rgbrow[0:2], 16),
                        int(rgbrow[2:4], 16),
                        int(rgbrow[4:6], 16),
                    )
                )
            pass_values.append(row)
        else:
            pass_values.append(int(val))

    try:
        payload = getattr(libwootility.libwootility_report, report)(*pass_values)
    except AttributeError:
        payload = None

    device.send_buffer(payload)


@main.command()
@click.option("--device", required=True)
@click.option("--feature", required=True)
@click.option("--value", multiple=True, type=int)
def libwootility_feature(device, feature, value):
    device = libwootility_device.get_device(device)

    payload = None

    try:
        payload = getattr(libwootility.libwootility_feature, feature)(*value)
    except AttributeError:
        payload = None

    if payload is None:
        print(f"Cannot create payload for {feature}")
    else:
        print(device.send_feature(payload))
