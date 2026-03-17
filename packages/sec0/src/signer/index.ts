import nacl from "tweetnacl";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";

export interface Signer {
  readonly keyId: string;
  sign(data: Uint8Array): Promise<Uint8Array> | Uint8Array;
}

export interface Verifier {
  verify(data: Uint8Array, signature: Uint8Array): Promise<boolean> | boolean;
}

const DEFAULT_SIGNER_KEY_DIRS = [
  path.resolve(process.cwd(), ".sec0/keys"),
  path.resolve(process.cwd(), "keys"),
  path.resolve(process.cwd(), "config/keys"),
  path.resolve(process.cwd(), ".sec0/secrets"),
  path.resolve(process.cwd(), "secrets"),
];

function parseAllowedSignerDirs(raw: string | undefined): string[] {
  if (!raw || raw.trim().length === 0) return DEFAULT_SIGNER_KEY_DIRS;
  return raw
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => path.resolve(entry));
}

function isWithinAllowedDir(candidate: string, allowedDir: string): boolean {
  const rel = path.relative(allowedDir, candidate);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

function resolveAllowedSignerKeyPath(keyRef: string): string {
  const rawPath = keyRef.slice("file://".length).trim();
  if (!rawPath) {
    throw new Error("[sec0-signer] keyRef file path is empty");
  }
  const resolvedPath = path.resolve(rawPath);
  const allowedDirs = parseAllowedSignerDirs(process.env.SEC0_SIGNER_KEY_DIRS);
  if (!allowedDirs.some((allowedDir) => isWithinAllowedDir(resolvedPath, allowedDir))) {
    throw new Error(
      `[sec0-signer] keyRef path "${resolvedPath}" is outside allowed directories. Set SEC0_SIGNER_KEY_DIRS to permit it.`,
    );
  }
  return resolvedPath;
}

/**
 * Compute the SHA-256 digest of the provided data and return it as a hex string.
 */
export function sha256Hex(data: Uint8Array | string): string {
  const hash = createHash("sha256");
  hash.update(typeof data === "string" ? Buffer.from(data) : Buffer.from(data));
  return hash.digest("hex");
}

/**
 * Canonicalize an object by sorting keys recursively before stringifying.
 */
export function canonicalize(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortKeys((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

/**
 * LocalDevSigner loads an ED25519 key from disk, signs payloads, and verifies signatures.
 */
export class LocalDevSigner implements Signer, Verifier {
  private secretKey: Uint8Array; // 64 bytes
  readonly publicKey: Uint8Array; // 32 bytes
  readonly keyId: string;

  private constructor(secretKey: Uint8Array) {
    this.secretKey = secretKey;
    const kp = nacl.sign.keyPair.fromSecretKey(secretKey);
    this.publicKey = kp.publicKey;
    this.keyId = `ed25519:${sha256Hex(kp.publicKey)}`;
  }

  // Create a signer from a file:// key reference pointing to a base64-encoded key.
  static fromKeyRef(keyRef: string): LocalDevSigner {
    if (!keyRef) {
      throw new Error("[sec0-signer] keyRef is required to load the ED25519 signer");
    }
    if (!keyRef.startsWith("file://")) {
      throw new Error(`[sec0-signer] Unsupported keyRef "${keyRef}". Only file:// key refs are supported.`);
    }
    const keyPath = resolveAllowedSignerKeyPath(keyRef);

    let content: Buffer;
    try {
      content = readFileSync(keyPath);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`[sec0-signer] Failed to read signing key file "${keyPath}": ${message}`);
    }

    // Expect base64 of 32 or 64 bytes
    const raw = Buffer.from(content.toString().trim(), "base64");
    if (raw.length !== 64 && raw.length !== 32) {
      throw new Error("[sec0-signer] Signing key must be base64 for a 32-byte seed or 64-byte secret key");
    }
    const secretKey = raw.length === 64 ? new Uint8Array(raw) : nacl.sign.keyPair.fromSeed(new Uint8Array(raw)).secretKey;
    return new LocalDevSigner(secretKey);
  }

  // Produce an ED25519 signature for the provided message bytes.
  sign(data: Uint8Array): Uint8Array {
    return nacl.sign.detached(data, this.secretKey);
  }

  // Verify an ED25519 signature for the provided message bytes.
  verify(data: Uint8Array, signature: Uint8Array): boolean {
    const kp = nacl.sign.keyPair.fromSecretKey(this.secretKey);
    return nacl.sign.detached.verify(data, signature, kp.publicKey);
  }
}

/**
 * Convert a Uint8Array into a base64 string.
 */
export function toBase64(u8: Uint8Array): string {
  return Buffer.from(u8).toString("base64");
}

/**
 * Convert a base64 string into a Uint8Array.
 */
export function fromBase64(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}
