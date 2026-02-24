from . import (
    menu_1_status,
    menu_2_user,
    menu_3_quota,
    menu_4_network,
    menu_5_domain,
    menu_6_speedtest,
    menu_7_security,
    menu_8_maintenance,
    menu_12_traffic,
)

MENU_HANDLERS = {
    "1": menu_1_status.handle,
    "2": menu_2_user.handle,
    "3": menu_3_quota.handle,
    "4": menu_4_network.handle,
    "5": menu_5_domain.handle,
    "6": menu_6_speedtest.handle,
    "7": menu_7_security.handle,
    "8": menu_8_maintenance.handle,
    "12": menu_12_traffic.handle,
}
