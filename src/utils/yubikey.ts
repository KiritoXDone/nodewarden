const YUBIKEY_OTP_REGEX = /^[cbdefghijklnrtuv]{44}$/;
const YUBIKEY_PUBLIC_ID_REGEX = /^[cbdefghijklnrtuv]{12}$/;
const DEFAULT_YUBICO_API_URL = 'https://api.yubico.com/wsapi/2.0/verify';
export const MAX_YUBIKEY_KEYS = 5;

function randomNonce(length: number = 32): string {
  const bytes = crypto.getRandomValues(new Uint8Array(Math.max(1, Math.ceil(length / 2))));
  return Array.from(bytes).map((byte) => byte.toString(16).padStart(2, '0')).join('').slice(0, length);
}

function base64ToBytes(input: string): Uint8Array {
  const normalized = String(input || '').trim();
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function buildSigningString(fields: Record<string, string>): string {
  return Object.keys(fields)
    .sort()
    .map((key) => `${key}=${fields[key]}`)
    .join('&');
}

async function signBase64HmacSha1(message: string, base64Secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    base64ToBytes(base64Secret),
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return bytesToBase64(new Uint8Array(signature));
}

function parseYubicoResponse(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of String(text || '').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const index = trimmed.indexOf('=');
    if (index <= 0) continue;
    const key = trimmed.slice(0, index);
    const value = trimmed.slice(index + 1);
    out[key] = value;
  }
  return out;
}

export function isValidYubikeyOtp(otpRaw: string): boolean {
  return YUBIKEY_OTP_REGEX.test(String(otpRaw || '').trim().toLowerCase());
}

export function isValidYubikeyPublicId(publicIdRaw: string): boolean {
  return YUBIKEY_PUBLIC_ID_REGEX.test(String(publicIdRaw || '').trim().toLowerCase());
}

export function normalizeYubikeyPublicId(value: string): string {
  return String(value || '').trim().toLowerCase();
}

export function extractYubikeyPublicId(otpRaw: string): string | null {
  const otp = String(otpRaw || '').trim().toLowerCase();
  if (!isValidYubikeyOtp(otp)) return null;
  return otp.slice(0, 12);
}

function normalizeYubikeyFlag(value: unknown): boolean {
  if (typeof value === 'boolean') return value;
  const normalized = String(value || '').trim().toLowerCase();
  return ['1', 'true', 'yes', 'on'].includes(normalized);
}

export interface StoredYubikeyOtpConfig {
  keys: string[];
  nfc: boolean;
}

export function normalizeYubikeyKeys(input: unknown, maxKeys: number = MAX_YUBIKEY_KEYS): string[] {
  if (!Array.isArray(input)) return [];
  const seen = new Set<string>();
  const normalized: string[] = [];
  for (const value of input) {
    const publicId = normalizeYubikeyPublicId(String(value || ''));
    if (!isValidYubikeyPublicId(publicId) || seen.has(publicId)) continue;
    seen.add(publicId);
    normalized.push(publicId);
    if (maxKeys > 0 && normalized.length >= maxKeys) break;
  }
  return normalized;
}


export function parseStoredYubikeyOtpConfig(input: unknown): StoredYubikeyOtpConfig {
  if (typeof input !== 'string' || !input.trim()) {
    return { keys: [], nfc: false };
  }

  try {
    const parsed = JSON.parse(input);
    if (Array.isArray(parsed)) {
      return { keys: normalizeYubikeyKeys(parsed), nfc: false };
    }
    if (parsed && typeof parsed === 'object') {
      const record = parsed as Record<string, unknown>;
      return {
        keys: normalizeYubikeyKeys(record.keys ?? record.Keys ?? record.publicIds ?? record.PublicIds),
        nfc: normalizeYubikeyFlag(record.nfc ?? record.Nfc),
      };
    }
  } catch {
    return { keys: [], nfc: false };
  }

  return { keys: [], nfc: false };
}

export function serializeStoredYubikeyOtpConfig(config: StoredYubikeyOtpConfig): string | null {
  const keys = normalizeYubikeyKeys(config.keys);
  if (!keys.length) return null;
  return JSON.stringify({
    keys,
    nfc: !!config.nfc,
  });
}

export function buildYubikeyProviderData(config: StoredYubikeyOtpConfig): { Nfc: boolean } | null {
  if (!config.keys.length) return null;
  return { Nfc: !!config.nfc };
}

export function resolveYubicoApiUrl(apiUrl?: string, server?: string): string {
  const normalizedApiUrl = String(apiUrl || '').trim();
  if (normalizedApiUrl) {
    if (/^https?:\/\//i.test(normalizedApiUrl)) return normalizedApiUrl;
    return `https://${normalizedApiUrl.replace(/^\/+/, '')}`;
  }

  const normalizedServer = String(server || '').trim();
  if (!normalizedServer) return DEFAULT_YUBICO_API_URL;
  if (/^https?:\/\//i.test(normalizedServer)) return normalizedServer;
  if (normalizedServer.includes('/')) return `https://${normalizedServer}`;
  return `https://${normalizedServer.replace(/\/+$/, '')}/wsapi/2.0/verify`;
}

export interface VerifyYubikeyOtpOptions {
  clientId: string;
  secretKey?: string;
  apiUrl?: string;
  server?: string;
}

export interface VerifyYubikeyOtpResult {
  ok: boolean;
  status: string;
  publicId: string | null;
}

export async function verifyYubikeyOtpWithYubico(
  otpRaw: string,
  options: VerifyYubikeyOtpOptions
): Promise<VerifyYubikeyOtpResult> {
  const otp = String(otpRaw || '').trim().toLowerCase();
  const publicId = extractYubikeyPublicId(otp);
  const clientId = String(options.clientId || '').trim();
  const secretKey = String(options.secretKey || '').trim();
  const apiUrl = resolveYubicoApiUrl(options.apiUrl, options.server);

  if (!publicId || !clientId) {
    return { ok: false, status: 'BAD_OTP', publicId };
  }

  const nonce = randomNonce(32);
  const requestFields: Record<string, string> = {
    id: clientId,
    nonce,
    otp,
  };

  if (secretKey) {
    requestFields.h = await signBase64HmacSha1(buildSigningString(requestFields), secretKey);
  }

  const requestUrl = `${apiUrl}?${new URLSearchParams(requestFields).toString()}`;
  const resp = await fetch(requestUrl, { method: 'GET' });
  if (!resp.ok) {
    return { ok: false, status: 'BACKEND_ERROR', publicId };
  }

  const responseFields = parseYubicoResponse(await resp.text());
  const status = String(responseFields.status || 'BACKEND_ERROR').trim();

  if (String(responseFields.otp || '').trim().toLowerCase() !== otp) {
    return { ok: false, status: 'BAD_OTP', publicId };
  }
  if (String(responseFields.nonce || '').trim() !== nonce) {
    return { ok: false, status: 'BAD_NONCE', publicId };
  }
  const responseClientId = String(responseFields.id || '').trim();
  if (responseClientId && responseClientId !== clientId) {
    return { ok: false, status: 'BAD_CLIENT', publicId };
  }

  if (secretKey) {
    const responseSignature = String(responseFields.h || '').trim();
    if (!responseSignature) {
      return { ok: false, status: 'BAD_SIGNATURE', publicId };
    }
    const fieldsWithoutSignature: Record<string, string> = {};
    for (const [key, value] of Object.entries(responseFields)) {
      if (key === 'h') continue;
      fieldsWithoutSignature[key] = value;
    }
    const expectedSignature = await signBase64HmacSha1(buildSigningString(fieldsWithoutSignature), secretKey);
    if (responseSignature !== expectedSignature) {
      return { ok: false, status: 'BAD_SIGNATURE', publicId };
    }
  }

  return { ok: status === 'OK', status, publicId };
}
