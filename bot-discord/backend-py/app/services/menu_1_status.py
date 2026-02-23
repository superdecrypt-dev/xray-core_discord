from ..adapters import system
from ..utils.response import error_response, ok_response


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
    return error_response("unknown_action", "Status & Diagnostics", f"Action tidak dikenal: {action}")
