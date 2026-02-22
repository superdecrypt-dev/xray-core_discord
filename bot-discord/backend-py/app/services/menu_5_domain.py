from ..adapters import system
from ..utils.response import error_response, ok_response


def handle(action: str, params: dict, settings) -> dict:
    if action == "domain_info":
        title, msg = system.op_domain_info()
        return ok_response(title, msg)
    if action == "nginx_server_name":
        title, msg = system.op_domain_nginx_server_name()
        return ok_response(title, msg)
    return error_response("unknown_action", "Domain Control", f"Action tidak dikenal: {action}")
