from ..adapters import system
from ..utils.response import error_response, ok_response
from ..utils.validators import parse_lines, require_param


def handle(action: str, params: dict, settings) -> dict:
    if action == "service_status":
        title, msg = system.op_maintenance_status()
        return ok_response(title, msg)

    if action in {"restart_xray", "restart_nginx"}:
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Maintenance", "Dangerous actions dinonaktifkan via env.")
        svc = "xray" if action == "restart_xray" else "nginx"
        title, msg = system.op_restart_service(svc)
        return ok_response(title, msg)

    if action == "tail_log":
        ok, service_or_err = require_param(params, "service", "Maintenance - Tail Log")
        if not ok:
            return service_or_err
        lines = parse_lines(params, default=80)
        title, msg = system.op_tail_log(service_or_err, lines)
        return ok_response(title, msg)

    return error_response("unknown_action", "Maintenance", f"Action tidak dikenal: {action}")
