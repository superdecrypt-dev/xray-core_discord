from ..adapters import system
from ..utils.response import error_response, ok_response


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

    return error_response("unknown_action", "Maintenance", f"Action tidak dikenal: {action}")
