import axios, { AxiosInstance } from "axios";

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
      timeout: 30000,
      headers: {
        "X-Internal-Shared-Secret": sharedSecret,
      },
    });
  }

  async runAction(menuId: string, action: string, params: Record<string, string> = {}): Promise<BackendActionResponse> {
    const res = await this.client.post<BackendActionResponse>(`/api/menu/${menuId}/action`, {
      action,
      params,
    });
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
