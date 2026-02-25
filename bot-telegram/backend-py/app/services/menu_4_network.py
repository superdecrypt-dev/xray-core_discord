from ..adapters import system, system_mutations
from ..utils.response import error_response, ok_response
from ..utils.validators import require_param, require_protocol, require_username


def handle(action: str, params: dict, settings) -> dict:
    if action == "egress_summary":
        title, msg = system.op_network_outbound_summary()
        return ok_response(title, msg)

    if action == "set_egress_mode":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Network Controls", "Dangerous actions dinonaktifkan via env.")
        ok_m, mode_or_err = require_param(params, "mode", "Network Controls - Set Egress Mode")
        if not ok_m:
            return mode_or_err
        ok_op, title, msg = system_mutations.op_network_set_egress_mode(str(mode_or_err))
        if ok_op:
            return ok_response(title, msg)
        return error_response("network_egress_mode_failed", title, msg)

    if action == "set_balancer_strategy":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Network Controls", "Dangerous actions dinonaktifkan via env.")
        ok_s, strategy_or_err = require_param(params, "strategy", "Network Controls - Balancer Strategy")
        if not ok_s:
            return strategy_or_err
        ok_op, title, msg = system_mutations.op_network_set_balancer_strategy(str(strategy_or_err))
        if ok_op:
            return ok_response(title, msg)
        return error_response("network_balancer_strategy_failed", title, msg)

    if action == "set_balancer_selector":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Network Controls", "Dangerous actions dinonaktifkan via env.")
        ok_sel, selector_or_err = require_param(params, "selector", "Network Controls - Balancer Selector")
        if not ok_sel:
            return selector_or_err
        ok_op, title, msg = system_mutations.op_network_set_balancer_selector(str(selector_or_err))
        if ok_op:
            return ok_response(title, msg)
        return error_response("network_balancer_selector_failed", title, msg)

    if action == "set_balancer_selector_auto":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Network Controls", "Dangerous actions dinonaktifkan via env.")
        ok_op, title, msg = system_mutations.op_network_set_balancer_selector_auto()
        if ok_op:
            return ok_response(title, msg)
        return error_response("network_balancer_selector_failed", title, msg)

    if action == "warp_status":
        title, msg = system.op_network_warp_status_report()
        return ok_response(title, msg)

    if action == "warp_restart":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Network Controls", "Dangerous actions dinonaktifkan via env.")
        ok_op, title, msg = system_mutations.op_network_warp_restart()
        if ok_op:
            return ok_response(title, msg)
        return error_response("network_warp_restart_failed", title, msg)

    if action == "set_warp_global_mode":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Network Controls", "Dangerous actions dinonaktifkan via env.")
        ok_m, mode_or_err = require_param(params, "mode", "Network Controls - WARP Global Mode")
        if not ok_m:
            return mode_or_err
        ok_op, title, msg = system_mutations.op_network_warp_set_global_mode(str(mode_or_err))
        if ok_op:
            return ok_response(title, msg)
        return error_response("network_warp_global_mode_failed", title, msg)

    if action == "set_warp_user_mode":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Network Controls", "Dangerous actions dinonaktifkan via env.")
        title = "Network Controls - WARP per-user"
        ok_p, proto_or_err = require_protocol(params, title)
        if not ok_p:
            return proto_or_err
        ok_u, user_or_err = require_username(params, title)
        if not ok_u:
            return user_or_err
        ok_m, mode_or_err = require_param(params, "mode", title)
        if not ok_m:
            return mode_or_err
        ok_op, t, m = system_mutations.op_network_warp_set_user_mode(proto_or_err, user_or_err, str(mode_or_err))
        if ok_op:
            return ok_response(t, m)
        return error_response("network_warp_user_mode_failed", t, m)

    if action == "set_warp_inbound_mode":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Network Controls", "Dangerous actions dinonaktifkan via env.")
        ok_t, tag_or_err = require_param(params, "inbound_tag", "Network Controls - WARP per-inbound")
        if not ok_t:
            return tag_or_err
        ok_m, mode_or_err = require_param(params, "mode", "Network Controls - WARP per-inbound")
        if not ok_m:
            return mode_or_err
        ok_op, title, msg = system_mutations.op_network_warp_set_inbound_mode(str(tag_or_err), str(mode_or_err))
        if ok_op:
            return ok_response(title, msg)
        return error_response("network_warp_inbound_mode_failed", title, msg)

    if action == "set_warp_domain_mode":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Network Controls", "Dangerous actions dinonaktifkan via env.")
        ok_m, mode_or_err = require_param(params, "mode", "Network Controls - WARP per-domain")
        if not ok_m:
            return mode_or_err
        ok_e, entry_or_err = require_param(params, "entry", "Network Controls - WARP per-domain")
        if not ok_e:
            return entry_or_err
        ok_op, title, msg = system_mutations.op_network_warp_set_domain_mode(str(mode_or_err), str(entry_or_err))
        if ok_op:
            return ok_response(title, msg)
        return error_response("network_warp_domain_mode_failed", title, msg)

    if action == "warp_tier_status":
        title, msg = system.op_network_warp_tier_status()
        return ok_response(title, msg)

    if action == "warp_tier_switch_free":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Network Controls", "Dangerous actions dinonaktifkan via env.")
        ok_op, title, msg = system_mutations.op_network_warp_tier_switch_free()
        if ok_op:
            return ok_response(title, msg)
        return error_response("network_warp_tier_switch_failed", title, msg)

    if action == "warp_tier_switch_plus":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Network Controls", "Dangerous actions dinonaktifkan via env.")
        license_key = str(params.get("license_key", "")).strip()
        ok_op, title, msg = system_mutations.op_network_warp_tier_switch_plus(license_key)
        if ok_op:
            return ok_response(title, msg)
        return error_response("network_warp_tier_switch_failed", title, msg)

    if action == "warp_tier_reconnect":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Network Controls", "Dangerous actions dinonaktifkan via env.")
        ok_op, title, msg = system_mutations.op_network_warp_tier_reconnect()
        if ok_op:
            return ok_response(title, msg)
        return error_response("network_warp_tier_reconnect_failed", title, msg)

    if action == "dns_summary":
        title, msg = system.op_dns_summary()
        return ok_response(title, msg)

    if action == "set_dns_primary":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Network Controls", "Dangerous actions dinonaktifkan via env.")
        ok_d, dns_or_err = require_param(params, "dns", "Network Controls - Set Primary DNS")
        if not ok_d:
            return dns_or_err
        ok_op, title, msg = system_mutations.op_network_set_dns_primary(str(dns_or_err))
        if ok_op:
            return ok_response(title, msg)
        return error_response("network_dns_primary_failed", title, msg)

    if action == "set_dns_secondary":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Network Controls", "Dangerous actions dinonaktifkan via env.")
        ok_d, dns_or_err = require_param(params, "dns", "Network Controls - Set Secondary DNS")
        if not ok_d:
            return dns_or_err
        ok_op, title, msg = system_mutations.op_network_set_dns_secondary(str(dns_or_err))
        if ok_op:
            return ok_response(title, msg)
        return error_response("network_dns_secondary_failed", title, msg)

    if action == "set_dns_query_strategy":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Network Controls", "Dangerous actions dinonaktifkan via env.")
        ok_q, query_or_err = require_param(params, "strategy", "Network Controls - Set DNS Query Strategy")
        if not ok_q:
            return query_or_err
        ok_op, title, msg = system_mutations.op_network_set_dns_query_strategy(str(query_or_err))
        if ok_op:
            return ok_response(title, msg)
        return error_response("network_dns_query_strategy_failed", title, msg)

    if action == "toggle_dns_cache":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Network Controls", "Dangerous actions dinonaktifkan via env.")
        ok_op, title, msg = system_mutations.op_network_toggle_dns_cache()
        if ok_op:
            return ok_response(title, msg)
        return error_response("network_dns_cache_toggle_failed", title, msg)

    if action == "state_file":
        title, msg = system.op_network_state_raw()
        return ok_response(title, msg)
    return error_response("unknown_action", "Network Controls", f"Action tidak dikenal: {action}")
