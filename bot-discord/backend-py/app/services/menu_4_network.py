from ..adapters import system
from ..utils.response import error_response, ok_response


def handle(action: str, params: dict, settings) -> dict:
    if action == "egress_summary":
        title, msg = system.op_network_outbound_summary()
        return ok_response(title, msg)
    if action == "dns_summary":
        title, msg = system.op_dns_summary()
        return ok_response(title, msg)
    if action == "state_file":
        title, msg = system.op_network_state_raw()
        return ok_response(title, msg)
    return error_response("unknown_action", "Network Controls", f"Action tidak dikenal: {action}")
