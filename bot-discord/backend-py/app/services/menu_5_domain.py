from ..adapters import system, system_mutations
from ..utils.response import error_response, ok_response
from ..utils.validators import parse_bool_value, require_param


def handle(action: str, params: dict, settings) -> dict:
    if action == "domain_info":
        title, msg = system.op_domain_info()
        return ok_response(title, msg)
    if action == "nginx_server_name":
        title, msg = system.op_domain_nginx_server_name()
        return ok_response(title, msg)
    if action == "cloudflare_root_list":
        ok_list, title, msg = system_mutations.op_domain_cloudflare_root_list()
        if ok_list:
            return ok_response(title, msg)
        return error_response("domain_root_list_failed", title, msg)
    if action == "setup_domain_custom":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Domain Control", "Dangerous actions dinonaktifkan via env.")
        ok_d, domain_or_err = require_param(params, "domain", "Domain Control - Set Domain (Custom)")
        if not ok_d:
            return domain_or_err
        ok_set, title, msg = system_mutations.op_domain_setup_custom(str(domain_or_err))
        if ok_set:
            return ok_response(title, msg)
        return error_response("setup_domain_custom_failed", title, msg)
    if action == "setup_domain_cloudflare":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Domain Control", "Dangerous actions dinonaktifkan via env.")
        title = "Domain Control - Set Domain (Cloudflare)"
        ok_r, root_or_err = require_param(params, "root_domain", title)
        if not ok_r:
            return root_or_err
        subdomain_mode = str(params.get("subdomain_mode", "auto") or "auto")
        subdomain = str(params.get("subdomain", "") or "")
        proxied = False
        proxied_raw = str(params.get("proxied", "") or "").strip()
        if proxied_raw:
            proxied_parsed = parse_bool_value(proxied_raw, default=None)
            if proxied_parsed is None:
                return error_response(
                    "invalid_param",
                    title,
                    "Parameter 'proxied' harus on/off atau true/false.",
                )
            proxied = bool(proxied_parsed)

        allow_existing = False
        allow_existing_raw = str(params.get("allow_existing_same_ip", "") or "").strip()
        if allow_existing_raw:
            allow_existing_parsed = parse_bool_value(allow_existing_raw, default=None)
            if allow_existing_parsed is None:
                return error_response(
                    "invalid_param",
                    title,
                    "Parameter 'allow_existing_same_ip' harus on/off atau true/false.",
                )
            allow_existing = bool(allow_existing_parsed)

        ok_set, title, msg = system_mutations.op_domain_setup_cloudflare(
            root_domain_input=str(root_or_err),
            subdomain_mode=subdomain_mode,
            subdomain=subdomain,
            proxied=bool(proxied),
            allow_existing_same_ip=bool(allow_existing),
        )
        if ok_set:
            return ok_response(title, msg)
        return error_response("setup_domain_cloudflare_failed", title, msg)
    if action == "set_domain":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Domain Control", "Dangerous actions dinonaktifkan via env.")
        ok_d, domain_or_err = require_param(params, "domain", "Domain Control - Set Domain")
        if not ok_d:
            return domain_or_err
        issue_cert = parse_bool_value(params.get("issue_cert"), default=False)
        ok_set, title, msg = system_mutations.op_domain_set(str(domain_or_err), issue_cert=bool(issue_cert))
        if ok_set:
            return ok_response(title, msg)
        return error_response("set_domain_failed", title, msg)
    if action == "refresh_account_info":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Domain Control", "Dangerous actions dinonaktifkan via env.")
        ok_ref, title, msg = system_mutations.op_domain_refresh_accounts()
        if ok_ref:
            return ok_response(title, msg)
        return error_response("domain_refresh_failed", title, msg)
    return error_response("unknown_action", "Domain Control", f"Action tidak dikenal: {action}")
