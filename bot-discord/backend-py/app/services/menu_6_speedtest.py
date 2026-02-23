from ..adapters import system
from ..utils.response import error_response, ok_response


def handle(action: str, params: dict, settings) -> dict:
    if action == "run":
        ok, title, msg = system.op_speedtest_run()
        if ok:
            return ok_response(title, msg)
        return error_response("speedtest_run_failed", title, msg)
    if action == "version":
        ok, title, msg = system.op_speedtest_version()
        if ok:
            return ok_response(title, msg)
        return error_response("speedtest_version_failed", title, msg)
    return error_response("unknown_action", "Speedtest", f"Action tidak dikenal: {action}")
