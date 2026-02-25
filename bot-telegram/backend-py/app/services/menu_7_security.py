from ..adapters import system
from ..utils.response import error_response, ok_response


def handle(action: str, params: dict, settings) -> dict:
    if action == "fail2ban_status":
        title, msg = system.op_fail2ban_status()
        return ok_response(title, msg)
    if action == "sysctl_summary":
        title, msg = system.op_sysctl_summary()
        return ok_response(title, msg)
    return error_response("unknown_action", "Security", f"Action tidak dikenal: {action}")
