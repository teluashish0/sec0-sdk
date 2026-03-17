const DEFAULT_CONTROL_PLANE_URL = "https://api.sec0.ai";

function readEnv(name: string): string | undefined {
  try {
    const value = typeof process !== "undefined" ? process.env?.[name] : undefined;
    const trimmed = typeof value === "string" ? value.trim() : "";
    return trimmed ? trimmed : undefined;
  } catch {
    return undefined;
  }
}

export function resolveControlPlaneUrl(explicit?: string): string {
  const envOverride =
    readEnv("SEC0_CONTROL_PLANE_URL") ||
    readEnv("CONTROL_PLANE_URL") ||
    readEnv("API_BASE_URL");
  const raw = String(explicit || "").trim() || envOverride || DEFAULT_CONTROL_PLANE_URL;
  const normalized = raw.replace(/\/+$/, "");
  if (!normalized) {
    throw new Error("[sec0-middleware] controlPlaneUrl could not be resolved");
  }
  return normalized;
}

export { DEFAULT_CONTROL_PLANE_URL };
