import type { Env, User, YubikeyOtpConfig } from '../types';
import { recoveryCodeEquals } from '../utils/recovery-code';
import { isTotpEnabled, verifyTotpToken } from '../utils/totp';
import {
  extractYubikeyPublicId,
  MAX_YUBIKEY_KEYS,
  normalizeYubikeyKeys,
  verifyYubikeyOtpWithYubico,
} from '../utils/yubikey';

interface WebYubikeyStatusResponse {
  enabled: boolean;
  publicIds: string[];
  keys: string[];
  nfc: boolean;
  object: 'twoFactorYubikey';
}

interface YubicoVerifyOptions {
  clientId: string;
  secretKey: string;
  apiUrl?: string;
  server?: string;
}

export function getYubicoVerifyOptions(
  env: Pick<Env, 'YUBICO_CLIENT_ID' | 'YUBICO_SECRET_KEY' | 'YUBICO_API_URL' | 'YUBICO_SERVER'>,
): YubicoVerifyOptions | null {
  const clientId = String(env.YUBICO_CLIENT_ID || '').trim();
  const secretKey = String(env.YUBICO_SECRET_KEY || '').trim();
  if (!clientId || !secretKey) return null;
  return {
    clientId,
    secretKey,
    apiUrl: String(env.YUBICO_API_URL || '').trim() || undefined,
    server: String(env.YUBICO_SERVER || '').trim() || undefined,
  };
}

export function applyBoundYubikey(
  config: YubikeyOtpConfig,
  publicId: string,
  nfc: boolean,
): YubikeyOtpConfig {
  const keys = normalizeYubikeyKeys([...config.keys, publicId]).slice(0, MAX_YUBIKEY_KEYS);
  return { keys, nfc: keys.length > 0 ? !!nfc : false };
}

export function applyRemovedYubikey(config: YubikeyOtpConfig, publicId: string): YubikeyOtpConfig {
  const keys = normalizeYubikeyKeys(config.keys.filter((key) => key !== publicId));
  return { keys, nfc: keys.length > 0 ? !!config.nfc : false };
}

export function shouldKeepRecoveryCode(
  user: Pick<User, 'totpSecret'>,
  nextConfig: YubikeyOtpConfig,
): boolean {
  return !!user.totpSecret || nextConfig.keys.length > 0;
}

export function buildWebYubikeyStatus(config: YubikeyOtpConfig): WebYubikeyStatusResponse {
  const publicIds = normalizeYubikeyKeys(config.keys).slice(0, MAX_YUBIKEY_KEYS);
  return {
    enabled: publicIds.length > 0,
    publicIds,
    keys: publicIds,
    nfc: publicIds.length > 0 ? !!config.nfc : false,
    object: 'twoFactorYubikey',
  };
}

export function buildVaultwardenYubikeyStatus(config: YubikeyOtpConfig): Record<string, unknown> {
  const publicIds = normalizeYubikeyKeys(config.keys).slice(0, MAX_YUBIKEY_KEYS);
  const payload: Record<string, unknown> = {
    enabled: publicIds.length > 0,
    nfc: publicIds.length > 0 ? !!config.nfc : false,
    object: 'twoFactorU2f',
  };
  publicIds.forEach((publicId, index) => {
    payload[`Key${index + 1}`] = publicId;
  });
  return payload;
}

export function parseVaultwardenYubikeySlots(body: Record<string, unknown>): string[] {
  const slots: string[] = [];
  for (let index = 1; index <= MAX_YUBIKEY_KEYS; index++) {
    const value = String(body[`Key${index}`] ?? body[`key${index}`] ?? '').trim().toLowerCase();
    if (value) slots.push(value);
  }
  return slots;
}

export type YubikeyVerifyStatus =
  | 'ok'
  | 'not_configured'
  | 'invalid_format'
  | 'unregistered_key'
  | 'verification_failed'
  | 'replayed_otp';

export async function verifyRegisteredYubikeyOtp(args: {
  otp: string;
  config: YubikeyOtpConfig;
  env: Pick<Env, 'YUBICO_CLIENT_ID' | 'YUBICO_SECRET_KEY' | 'YUBICO_API_URL' | 'YUBICO_SERVER'>;
  markOtpUsed: (otp: string) => Promise<boolean>;
  verifyOtp?: typeof verifyYubikeyOtpWithYubico;
}): Promise<{ ok: boolean; status: YubikeyVerifyStatus; publicId: string | null }> {
  const otp = String(args.otp || '').trim().toLowerCase();
  const publicId = extractYubikeyPublicId(otp);
  if (!publicId) return { ok: false, status: 'invalid_format', publicId: null };

  const allowed = normalizeYubikeyKeys(args.config.keys);
  if (!allowed.includes(publicId)) {
    return { ok: false, status: 'unregistered_key', publicId };
  }

  const options = getYubicoVerifyOptions(args.env);
  if (!options) return { ok: false, status: 'not_configured', publicId };

  const verifier = args.verifyOtp || verifyYubikeyOtpWithYubico;
  const verified = await verifier(otp, options);
  if (!verified.ok || verified.publicId !== publicId) {
    return { ok: false, status: 'verification_failed', publicId };
  }

  const marked = await args.markOtpUsed(otp);
  if (!marked) return { ok: false, status: 'replayed_otp', publicId };

  return { ok: true, status: 'ok', publicId };
}

export async function verifyProtectedTwoFactorAccess(args: {
  masterPasswordHash: string | null;
  otp: string | null;
  user: Pick<User, 'email' | 'masterPasswordHash' | 'totpSecret' | 'totpRecoveryCode'>;
  verifyPassword: (candidate: string, storedHash: string, email: string) => Promise<boolean>;
  verifyTotp?: typeof verifyTotpToken;
  verifyYubikeyOtp: (otp: string) => Promise<{ ok: boolean }>;
}): Promise<boolean> {
  const masterPasswordHash = String(args.masterPasswordHash || '').trim();
  if (masterPasswordHash) {
    const ok = await args.verifyPassword(masterPasswordHash, args.user.masterPasswordHash, args.user.email);
    if (ok) return true;
  }

  const otp = String(args.otp || '').trim();
  if (!otp) return false;

  const totpVerifier = args.verifyTotp || verifyTotpToken;
  if (args.user.totpSecret && isTotpEnabled(args.user.totpSecret)) {
    const ok = await totpVerifier(args.user.totpSecret, otp);
    if (ok) return true;
  }

  if (recoveryCodeEquals(otp, args.user.totpRecoveryCode)) {
    return true;
  }

  const yubikeyResult = await args.verifyYubikeyOtp(otp);
  return yubikeyResult.ok;
}
