from ..adapters import system
from ..utils.response import error_response, ok_response
from ..utils.validators import require_param, require_positive_int_param


def handle(action: str, params: dict, settings) -> dict:
    if action == "overview":
        title, msg = system.op_traffic_analytics_overview()
        return ok_response(title, msg)

    if action == "top_users":
        title = "Traffic Analytics - Top Users"
        ok_l, limit_or_err = require_positive_int_param(params, "limit", title, minimum=1)
        if not ok_l:
            return limit_or_err
        title_top, msg_top = system.op_traffic_analytics_top_users(int(limit_or_err))
        return ok_response(title_top, msg_top)

    if action == "search_user":
        ok_q, query_or_err = require_param(params, "query", "Traffic Analytics - Search")
        if not ok_q:
            return query_or_err
        title_search, msg_search = system.op_traffic_analytics_search(str(query_or_err))
        return ok_response(title_search, msg_search)

    if action == "export_json":
        ok_export, title, msg, download = system.op_traffic_analytics_export_json()
        if ok_export and isinstance(download, dict):
            return ok_response(title, msg, data={"download_file": download})
        return error_response("traffic_export_failed", title, msg)

    return error_response("unknown_action", "Traffic Analytics", f"Action tidak dikenal: {action}")
