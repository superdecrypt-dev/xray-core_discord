from ..adapters import system
from ..utils.response import error_response, ok_response
from ..utils.validators import parse_lines


def handle(action: str, params: dict, settings) -> dict:
    if action == "overview":
        title, msg = system.op_status_overview()
        return ok_response(title, msg)
    if action == "xray_test":
        ok, title, msg = system.op_xray_test()
        if ok:
            return ok_response(title, msg)
        return error_response("xray_test_failed", title, msg)
    if action == "tls_info":
        ok, title, msg = system.op_tls_info()
        if ok:
            return ok_response(title, msg)
        return error_response("tls_info_failed", title, msg)
    if action == "observe_snapshot":
        ok, title, msg = system.op_observe_snapshot()
        if ok:
            return ok_response(title, msg)
        return error_response("observe_snapshot_failed", title, msg)
    if action == "observe_status":
        ok, title, msg = system.op_observe_status()
        if ok:
            return ok_response(title, msg)
        return error_response("observe_status_failed", title, msg)
    if action == "observe_alert_log":
        lines = parse_lines(params, default=80, minimum=20, maximum=300)
        ok, title, msg = system.op_observe_alert_log(lines=lines)
        if ok:
            return ok_response(title, msg)
        return error_response("observe_alert_log_failed", title, msg)
    return error_response("unknown_action", "Status & Diagnostics", f"Action tidak dikenal: {action}")
