import type { ControlPlaneClient } from "./controlPlaneClient";

type UploadApiConfig = { baseUrl: string; apiKey: string };

export async function uploadScanEvidence(opts: {
  kind: "sast" | "dast" | "agent_guard_findings";
  scanId: string;
  raw: unknown;
  uploadConfig?: UploadApiConfig;
  controlPlaneClientFactory: (baseUrl: string) => ControlPlaneClient;
}): Promise<string | null> {
  const apiBase = opts.uploadConfig?.baseUrl?.trim();
  if (!apiBase) throw new Error("upload_base_url_missing");
  const apiKey = opts.uploadConfig?.apiKey?.trim();
  if (!apiKey) throw new Error("upload_api_key_missing");

  const client = opts.controlPlaneClientFactory(apiBase);
  const presign = await client.requestUploadUrl({
    authToken: apiKey,
    body: {
      mode: "scan",
      scanKind: opts.kind,
      scanId: opts.scanId,
      contentType: "application/json",
    },
  });
  const bodyStr = typeof opts.raw === "string" ? opts.raw : JSON.stringify(opts.raw ?? {}, null, 2);
  await client.uploadToPresignedUrl({
    url: presign.url,
    headers: presign.headers || { "Content-Type": "application/json" },
    body: bodyStr,
  });
  return presign.key || null;
}
