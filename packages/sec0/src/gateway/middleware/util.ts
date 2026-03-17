/**
 * Utility to match a tool against a pattern that may include wildcards and
 * different forms (server:tool@version, server:tool, tool@version, tool, server).
 * Throws loudly when the pattern is missing or empty to avoid silent misconfig.
 * Check whether an MCP tool reference matches the provided pattern. Patterns
 * may include `*` wildcards and omit the server or version segment.
 */
export function matchesToolPattern(pattern: string, serverName: string, toolNameAtVersion: string): boolean {
  if (pattern === null || pattern === undefined) {
    throw new Error("[sec0-gateway] matchesToolPattern: pattern is required");
  }

  const patRaw = String(pattern).trim();
  if (!patRaw) {
    throw new Error("[sec0-gateway] matchesToolPattern: pattern must not be empty");
  }

  const pat = patRaw.toLowerCase();
  const toolRefFull = `${serverName}:${toolNameAtVersion}`.toLowerCase();
  const [toolBase] = toolNameAtVersion.split('@');
  const toolRefNoVersion = `${serverName}:${toolBase}`.toLowerCase();
  const toolWithVersion = toolNameAtVersion.toLowerCase();
  const toolOnly = toolBase.toLowerCase();
  const serverOnly = serverName.toLowerCase();

  if (pat.includes('*')) {
    const esc = pat.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*?');
    const re = new RegExp(`^${esc}$`, 'i');
    return (
      re.test(toolRefFull) ||
      re.test(toolRefNoVersion) ||
      re.test(toolWithVersion) ||
      re.test(toolOnly) ||
      re.test(serverOnly)
    );
  }

  return (
    pat === toolRefFull ||
    pat === toolRefNoVersion ||
    pat === toolWithVersion ||
    pat === toolOnly ||
    pat === serverOnly
  );
}
