export async function callBackend(action: string, payload: Record<string, unknown>): Promise<unknown> {
  // TODO: implement backend call with INTERNAL_SHARED_SECRET
  return { ok: false, action, payload, message: "not implemented" };
}
