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
        ok, title, msg = system.op_restart_service(svc)
        if ok:
            return ok_response(title, msg)
        return error_response("restart_service_failed", title, msg)

    if action == "tail_log":
        ok, service_or_err = require_param(params, "service", "Maintenance - Tail Log")
        if not ok:
            return service_or_err
        lines = parse_lines(params, default=80)
        ok_log, title, msg = system.op_tail_log(service_or_err, lines)
        if ok_log:
            return ok_response(title, msg)
        return error_response("tail_log_failed", title, msg)

    return error_response("unknown_action", "Maintenance", f"Action tidak dikenal: {action}")
