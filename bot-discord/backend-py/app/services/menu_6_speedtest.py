from ..adapters import system
from ..utils.response import error_response, ok_response


def handle(action: str, params: dict, settings) -> dict:
    if action == "run":
        title, msg = system.op_speedtest_run()
        return ok_response(title, msg)
    if action == "version":
        title, msg = system.op_speedtest_version()
        return ok_response(title, msg)
    return error_response("unknown_action", "Speedtest", f"Action tidak dikenal: {action}")
