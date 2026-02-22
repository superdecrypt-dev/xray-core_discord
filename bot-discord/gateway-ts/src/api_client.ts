import axios, { AxiosInstance } from "axios";

export interface BackendActionResponse {
  ok: boolean;
  code: string;
  title: string;
  message: string;
  data?: Record<string, unknown>;
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
}
