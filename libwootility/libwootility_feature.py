D1DA = b"\xd1\xda"


PING = 0x00
GET_VERSION = 0x01
RESET_TO_BOOTLOADER = 0x02
GET_SERIAL = 0x03
GET_RGB_PROFILE_COUNT = 0x04
REMOVED_GET_CURRENT_RGB_PROFILE_INDEX = 0x05
REMOVED_GET_RGB_MAIN_PROFILE = 0x06
RELOAD_PROFILE0 = 0x07
SAVE_RGB_PROFILE = 0x08
GET_DIGITAL_PROFILES_COUNT = 0x09
GET_ANALOG_PROFILES_COUNT = 0x0A
GET_CURRENT_KEYBOARD_PROFILE_INDEX = 0x0B
GET_DIGITAL_PROFILE = 0x0C
GET_ANALOG_PROFILE_MAIN_PART = 0x0D
GET_ANALOG_PROFILE_CURVE_CHANGE_MAP_PART1 = 0x0E
GET_ANALOG_PROFILE_CURVE_CHANGE_MAP_PART2 = 0x0F
GET_NUMBER_OF_KEYS = 0x10
GET_MAIN_MAPPING_PROFILE = 0x11
GET_FUNCTION_MAPPING_PROFILE = 0x12
GET_DEVICE_CONFIG = 0x13
GET_ANALOG_VALUES = 0x14
KEYS_OFF = 0x15
KEYS_ON = 0x16
ACTIVATE_PROFILE = 0x17
GET_DKS_PROFILE = 0x18
DO_SOFT_RESET = 0x19
REMOVED_GET_RGB_COLORS_PART1 = 0x1A
REMOVED_GET_RGB_COLORS_PART2 = 0x1B
REMOVED_GET_RGB_EFFECTS = 0x1C
REFRESH_RGB_COLORS = 0x1D
WOOT_DEV_SINGLE_COLOR = 0x1E
WOOT_DEV_RESET_COLOR = 0x1F
WOOT_DEV_RESET_ALL = 0x20
WOOT_DEV_INIT = 0x21
REMOVED_GET_RGB_PROFILE_BASE = 0x22
GET_RGB_PROFILE_COLOR_PART1 = 0x23
GET_RGB_PROFILE_COLOR_PART2 = 0x24
REMOVED_GET_RGB_PROFILE_EFFECT = 0x25
RELOAD_PROFILE = 0x26
GET_KEYBOARD_PROFILE = 0x27
GET_GAMEPAD_MAPPING = 0x28
GET_GAMEPAD_PROFILE = 0x29
SAVE_KEYBOARD_PROFILE = 0x2A
RESET_FLASH = 0x2B
SET_RAW_SCANNING = 0x2C
START_XINPUT_DETECTION = 0x2D
STOP_XINPUT_DETECTION = 0x2E
SAVE_DKS_PROFILE = 0x2F
GET_MAPPING_PROFILE = 0x30
GET_ACTUATION_PROFILE = 0x31
GET_RGB_PROFILE_CORE = 0x32
GET_GLOBAL_SETTINGS = 0x33
GET_AKC_PROFILE = 0x34
SAVE_AKC_PROFILE = 0x35
GET_RAPID_TRIGGER_PROFILE = 0x36
GET_PROFILE_METADATA = 0x37
IS_FLASH_CHIP_CONNECTED = 0x38
GET_RGB_LAYER = 0x39
GET_FLASH_STATS = 0x3A
GET_RGB_BINS = 0x3B

HAS_RESPONSE = [
    PING,
    GET_VERSION,
    GET_SERIAL,
    SAVE_RGB_PROFILE,
    REFRESH_RGB_COLORS,
    REMOVED_GET_CURRENT_RGB_PROFILE_INDEX,
    GET_CURRENT_KEYBOARD_PROFILE_INDEX,
    GET_ANALOG_VALUES,
    ACTIVATE_PROFILE,
    GET_DEVICE_CONFIG,
    GET_MAIN_MAPPING_PROFILE,
    GET_FUNCTION_MAPPING_PROFILE,
    KEYS_OFF,
    GET_DKS_PROFILE,
    KEYS_ON,
    DO_SOFT_RESET,
    WOOT_DEV_INIT,
    WOOT_DEV_RESET_ALL,
    START_XINPUT_DETECTION,
    STOP_XINPUT_DETECTION,
    RELOAD_PROFILE0,
]


def ping():
    return D1DA + bytes((PING,))


def get_version():
    return D1DA + bytes((GET_VERSION,))


def reset_to_bootloader():
    return D1DA + bytes((RESET_TO_BOOTLOADER,))


def get_serial():
    return D1DA + bytes((GET_SERIAL,))


def get_rgb_profile_count():
    return D1DA + bytes((GET_RGB_PROFILE_COUNT,))


def removed_get_current_rgb_profile_index():
    return D1DA + bytes((REMOVED_GET_CURRENT_RGB_PROFILE_INDEX,))


def removed_get_rgb_main_profile():
    return D1DA + bytes((REMOVED_GET_RGB_MAIN_PROFILE,))


def reload_profile0(index):
    return D1DA + bytes((RELOAD_PROFILE0, index))


def save_rgb_profile():
    return D1DA + bytes((SAVE_RGB_PROFILE,))


def get_digital_profiles_count():
    return D1DA + bytes((GET_DIGITAL_PROFILES_COUNT,))


def get_analog_profiles_count():
    return D1DA + bytes((GET_ANALOG_PROFILES_COUNT,))


def get_current_keyboard_profile_index():
    return D1DA + bytes((GET_CURRENT_KEYBOARD_PROFILE_INDEX,))


def get_digital_profile():
    return D1DA + bytes((GET_DIGITAL_PROFILE,))


def get_analog_profile_main_part():
    return D1DA + bytes((GET_ANALOG_PROFILE_MAIN_PART,))


def get_analog_profile_curve_change_map_part1():
    return D1DA + bytes((GET_ANALOG_PROFILE_CURVE_CHANGE_MAP_PART1,))


def get_analog_profile_curve_change_map_part2():
    return D1DA + bytes((GET_ANALOG_PROFILE_CURVE_CHANGE_MAP_PART2,))


def get_number_of_keys():
    return D1DA + bytes((GET_NUMBER_OF_KEYS,))


def get_main_mapping_profile():
    return D1DA + bytes((GET_MAIN_MAPPING_PROFILE,))


def get_function_mapping_profile():
    return D1DA + bytes((GET_FUNCTION_MAPPING_PROFILE,))


def get_device_config():
    return D1DA + bytes((GET_DEVICE_CONFIG,))


def get_analog_values():
    return D1DA + bytes((GET_ANALOG_VALUES,))


def keys_off():
    return D1DA + bytes((KEYS_OFF,))


def keys_on():
    return D1DA + bytes((KEYS_ON,))


def activate_profile(index):
    return D1DA + bytes((ACTIVATE_PROFILE, index))


def get_dks_profile():
    return D1DA + bytes((GET_DKS_PROFILE,))


def do_soft_reset():
    return D1DA + bytes((DO_SOFT_RESET,))


def removed_get_rgb_colors_part1():
    return D1DA + bytes((REMOVED_GET_RGB_COLORS_PART1,))


def removed_get_rgb_colors_part2():
    return D1DA + bytes((REMOVED_GET_RGB_COLORS_PART2,))


def removed_get_rgb_effects():
    return D1DA + bytes((REMOVED_GET_RGB_EFFECTS,))


def refresh_rgb_colors(index):
    return D1DA + bytes((REFRESH_RGB_COLORS, index))


def woot_dev_single_color(row, column, red, green, blue):
    id = (row << 5) | column
    return D1DA + bytes((WOOT_DEV_SINGLE_COLOR, blue, green, red, id))


def woot_dev_reset_color(row, column):
    id = (row << 5) | column
    return D1DA + bytes((WOOT_DEV_RESET_COLOR, id))


def woot_dev_reset_all():
    """
    Reset keyboard to wootility mode (after woot_dev_init)
    """
    return D1DA + bytes((WOOT_DEV_RESET_ALL,))


def woot_dev_init():
    """
    Initialize mode to manually set the RGB array using
    libwootility.libwootility_report.rgb_array_update_keyboard()
    """
    return D1DA + bytes((WOOT_DEV_INIT,))


def removed_get_rgb_profile_base():
    return D1DA + bytes((REMOVED_GET_RGB_PROFILE_BASE,))


def get_rgb_profile_color_part1():
    return D1DA + bytes((GET_RGB_PROFILE_COLOR_PART1,))


def get_rgb_profile_color_part2():
    return D1DA + bytes((GET_RGB_PROFILE_COLOR_PART2,))


def removed_get_rgb_profile_effect():
    return D1DA + bytes((REMOVED_GET_RGB_PROFILE_EFFECT,))


def reload_profile():
    return D1DA + bytes((RELOAD_PROFILE,))


def get_keyboard_profile():
    return D1DA + bytes((GET_KEYBOARD_PROFILE,))


def get_gamepad_mapping():
    return D1DA + bytes((GET_GAMEPAD_MAPPING,))


def get_gamepad_profile():
    return D1DA + bytes((GET_GAMEPAD_PROFILE,))


def save_keyboard_profile():
    return D1DA + bytes((SAVE_KEYBOARD_PROFILE,))


def reset_flash():
    return D1DA + bytes((RESET_FLASH,))


def set_raw_scanning():
    return D1DA + bytes((SET_RAW_SCANNING,))


def start_xinput_detection():
    return D1DA + bytes((START_XINPUT_DETECTION,))


def stop_xinput_detection():
    return D1DA + bytes((STOP_XINPUT_DETECTION,))


def save_dks_profile():
    return D1DA + bytes((SAVE_DKS_PROFILE,))


def get_mapping_profile():
    return D1DA + bytes((GET_MAPPING_PROFILE,))


def get_actuation_profile():
    return D1DA + bytes((GET_ACTUATION_PROFILE,))


def get_rgb_profile_core():
    return D1DA + bytes((GET_RGB_PROFILE_CORE,))


def get_global_settings():
    return D1DA + bytes((GET_GLOBAL_SETTINGS,))


def get_akc_profile():
    return D1DA + bytes((GET_AKC_PROFILE,))


def save_akc_profile():
    return D1DA + bytes((SAVE_AKC_PROFILE,))


def get_rapid_trigger_profile():
    return D1DA + bytes((GET_RAPID_TRIGGER_PROFILE,))


def get_profile_metadata():
    return D1DA + bytes((GET_PROFILE_METADATA,))


def is_flash_chip_connected():
    return D1DA + bytes((IS_FLASH_CHIP_CONNECTED,))


def get_rgb_layer():
    return D1DA + bytes((GET_RGB_LAYER,))


def get_flash_stats():
    return D1DA + bytes((GET_FLASH_STATS,))


def get_rgb_bins():
    return D1DA + bytes((GET_RGB_BINS,))
