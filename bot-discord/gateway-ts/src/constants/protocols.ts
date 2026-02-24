export const XRAY_PROTOCOLS = ["vless", "vmess", "trojan"] as const;

export type XrayProtocol = (typeof XRAY_PROTOCOLS)[number];

export function isXrayProtocol(value: string): value is XrayProtocol {
  return (XRAY_PROTOCOLS as readonly string[]).includes(value);
}

export const MENU2_PROTOCOL_SELECT_ACTIONS = ["add_user", "extend_expiry", "account_info"] as const;

export type Menu2ProtocolSelectAction = (typeof MENU2_PROTOCOL_SELECT_ACTIONS)[number];

export function isMenu2ProtocolSelectAction(value: string): value is Menu2ProtocolSelectAction {
  return (MENU2_PROTOCOL_SELECT_ACTIONS as readonly string[]).includes(value);
}

export function shouldUseProtocolSelect(menuId: string, actionId: string, hasProtoField: boolean): boolean {
  return hasProtoField || (menuId === "2" && isMenu2ProtocolSelectAction(actionId));
}

export function shouldUseUsernameSelect(actionId: string, hasUsernameField: boolean): boolean {
  return hasUsernameField && actionId !== "add_user";
}
