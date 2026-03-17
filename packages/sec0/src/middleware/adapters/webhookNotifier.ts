export async function postPolicyWebhookEvent(url: string, payload: Record<string, unknown>): Promise<void> {
  const endpoint = String(url || "").trim();
  if (!endpoint) return;
  await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  } as any);
}

export function fireAndForgetPolicyWebhookEvent(url: string, payload: Record<string, unknown>): void {
  const endpoint = String(url || "").trim();
  if (!endpoint) return;
  void postPolicyWebhookEvent(endpoint, payload).catch(() => {});
}
