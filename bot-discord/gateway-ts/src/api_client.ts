import axios, { AxiosInstance } from "axios";

const DEFAULT_BACKEND_TIMEOUT_MS = 30_000;
const ACTION_TIMEOUT_MS: Record<string, number> = {
  "5:setup_domain_custom": 420_000,
  "5:setup_domain_cloudflare": 420_000,
  "6:run": 190_000,
};

function resolveActionTimeoutMs(menuId: string, action: string): number {
  return ACTION_TIMEOUT_MS[`${menuId}:${action}`] ?? DEFAULT_BACKEND_TIMEOUT_MS;
}

export interface BackendActionResponse {
  ok: boolean;
  code: string;
  title: string;
  message: string;
  data?: Record<string, unknown>;
}

export interface BackendUserOption {
  proto: string;
  username: string;
}

export class BackendClient {
  private readonly client: AxiosInstance;

  constructor(baseURL: string, sharedSecret: string) {
    this.client = axios.create({
      baseURL,
      timeout: DEFAULT_BACKEND_TIMEOUT_MS,
      headers: {
        "X-Internal-Shared-Secret": sharedSecret,
      },
    });
  }

  async runAction(menuId: string, action: string, params: Record<string, string> = {}): Promise<BackendActionResponse> {
    const timeout = resolveActionTimeoutMs(menuId, action);
    const res = await this.client.post<BackendActionResponse>(
      `/api/menu/${menuId}/action`,
      {
        action,
        params,
      },
      {
        timeout,
      },
    );
    return res.data;
  }

  async listUserOptions(proto?: string): Promise<BackendUserOption[]> {
    const res = await this.client.get<{ users?: BackendUserOption[] }>("/api/users/options", {
      params: proto ? { proto } : {},
    });
    const users = Array.isArray(res.data?.users) ? res.data.users : [];
    return users.filter((item) => item && typeof item.proto === "string" && typeof item.username === "string");
  }
}
