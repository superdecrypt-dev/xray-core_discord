export interface ActionSingleSelectOption {
  label: string;
  value: string;
  description?: string;
}

export interface ActionSingleSelectConfig {
  fieldId: string;
  title: string;
  placeholder: string;
  options: readonly ActionSingleSelectOption[];
}

const NETWORK_SINGLE_SELECTS: Record<string, ActionSingleSelectConfig> = {
  set_egress_mode: {
    fieldId: "mode",
    title: "Set Egress Mode",
    placeholder: "Pilih mode egress",
    options: [
      { label: "DIRECT", value: "direct", description: "Lewat outbound direct" },
      { label: "WARP", value: "warp", description: "Lewat outbound warp" },
      { label: "BALANCER", value: "balancer", description: "Lewat balancer egress" },
    ],
  },
  set_balancer_strategy: {
    fieldId: "strategy",
    title: "Set Balancer Strategy",
    placeholder: "Pilih strategy balancer",
    options: [
      { label: "random", value: "random", description: "Pilih secara acak" },
      { label: "roundRobin", value: "roundRobin", description: "Rotasi berurutan" },
      { label: "leastPing", value: "leastPing", description: "Pilih ping paling rendah" },
      { label: "leastLoad", value: "leastLoad", description: "Pilih beban paling ringan" },
    ],
  },
  set_balancer_selector: {
    fieldId: "selector",
    title: "Set Balancer Selector",
    placeholder: "Pilih selector",
    options: [
      { label: "auto", value: "auto", description: "Otomatis pilih outbound valid" },
      { label: "direct,warp", value: "direct,warp", description: "Gunakan direct + warp" },
      { label: "direct", value: "direct", description: "Pakai direct saja" },
      { label: "warp", value: "warp", description: "Pakai warp saja" },
    ],
  },
  set_dns_query_strategy: {
    fieldId: "strategy",
    title: "Set DNS Query Strategy",
    placeholder: "Pilih query strategy",
    options: [
      { label: "UseIP", value: "UseIP", description: "Gunakan IPv4/IPv6 otomatis" },
      { label: "UseIPv4", value: "UseIPv4", description: "Paksa IPv4" },
      { label: "UseIPv6", value: "UseIPv6", description: "Paksa IPv6" },
      { label: "PreferIPv4", value: "PreferIPv4", description: "Prioritaskan IPv4" },
      { label: "PreferIPv6", value: "PreferIPv6", description: "Prioritaskan IPv6" },
    ],
  },
};

export function getSingleFieldSelectConfig(menuId: string, actionId: string): ActionSingleSelectConfig | null {
  if (menuId === "4") {
    return NETWORK_SINGLE_SELECTS[actionId] || null;
  }
  if (menuId === "5" && actionId === "setup_domain_cloudflare") {
    return {
      fieldId: "root_domain",
      title: "Cloudflare Root Domain",
      placeholder: "Pilih root domain Cloudflare",
      options: [
        { label: "vyxara1.web.id", value: "vyxara1.web.id", description: "Root domain 1" },
        { label: "vyxara2.web.id", value: "vyxara2.web.id", description: "Root domain 2" },
        { label: "vyxara1.qzz.io", value: "vyxara1.qzz.io", description: "Root domain 3" },
        { label: "vyxara2.qzz.io", value: "vyxara2.qzz.io", description: "Root domain 4" },
      ],
    };
  }
  return null;
}

export function shouldSelectContinueToModal(menuId: string, actionId: string): boolean {
  if (menuId === "5" && actionId === "setup_domain_cloudflare") {
    return true;
  }
  return false;
}

export function encodeSingleSelectPreset(fieldId: string, value: string): string {
  return `${fieldId}|${encodeURIComponent(value)}`;
}

export function decodeSingleSelectPreset(raw: string): { fieldId: string; value: string } | null {
  const source = String(raw || "").trim();
  if (!source || !source.includes("|")) {
    return null;
  }
  const idx = source.indexOf("|");
  const fieldId = source.slice(0, idx).trim();
  const encodedValue = source.slice(idx + 1).trim();
  if (!fieldId || !encodedValue) {
    return null;
  }
  try {
    return { fieldId, value: decodeURIComponent(encodedValue) };
  } catch {
    return { fieldId, value: encodedValue };
  }
}
