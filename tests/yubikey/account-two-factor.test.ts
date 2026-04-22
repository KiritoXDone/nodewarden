import test from 'node:test';
import assert from 'node:assert/strict';
import {
  applyBoundYubikey,
  applyRemovedYubikey,
  buildWebYubikeyStatus,
  buildVaultwardenYubikeyStatus,
  getYubicoVerifyOptions,
  parseVaultwardenYubikeySlots,
  shouldKeepRecoveryCode,
  verifyProtectedTwoFactorAccess,
  verifyRegisteredYubikeyOtp,
} from '../../src/services/account-two-factor.ts';

test('applyBoundYubikey adds a new public id once and preserves the latest nfc flag', () => {
  assert.deepEqual(
    applyBoundYubikey({ keys: ['cccccccccccc'], nfc: false }, 'dddddddddddd', true),
    { keys: ['cccccccccccc', 'dddddddddddd'], nfc: true },
  );
});

test('applyRemovedYubikey clears nfc when the last key is removed', () => {
  assert.deepEqual(applyRemovedYubikey({ keys: ['cccccccccccc'], nfc: true }, 'cccccccccccc'), {
    keys: [],
    nfc: false,
  });
});

test('shouldKeepRecoveryCode stays true when another factor remains enabled', () => {
  assert.equal(
    shouldKeepRecoveryCode({ totpSecret: 'JBSWY3DPEHPK3PXP' }, { keys: [], nfc: false }),
    true,
  );
});

test('shouldKeepRecoveryCode returns false when no factor remains enabled', () => {
  assert.equal(
    shouldKeepRecoveryCode({ totpSecret: null }, { keys: [], nfc: false }),
    false,
  );
});

test('buildVaultwardenYubikeyStatus returns disabled payload when no keys remain', () => {
  assert.deepEqual(buildVaultwardenYubikeyStatus({ keys: [], nfc: false }), {
    enabled: false,
    nfc: false,
    object: 'twoFactorU2f',
  });
});

test('buildWebYubikeyStatus returns normalized web payload', () => {
  assert.deepEqual(buildWebYubikeyStatus({ keys: ['cccccccccccc'], nfc: true }), {
    enabled: true,
    publicIds: ['cccccccccccc'],
    keys: ['cccccccccccc'],
    nfc: true,
    object: 'twoFactorYubikey',
  });
});

test('buildVaultwardenYubikeyStatus returns slot fields and twoFactorU2f object', () => {
  assert.deepEqual(buildVaultwardenYubikeyStatus({ keys: ['cccccccccccc', 'dddddddddddd'], nfc: false }), {
    Key1: 'cccccccccccc',
    Key2: 'dddddddddddd',
    enabled: true,
    nfc: false,
    object: 'twoFactorU2f',
  });
});

test('parseVaultwardenYubikeySlots keeps populated slots in order', () => {
  assert.deepEqual(
    parseVaultwardenYubikeySlots({ Key1: 'cccccccccccc', key3: 'dddddddddddd', Key5: '' }),
    ['cccccccccccc', 'dddddddddddd'],
  );
});

test('getYubicoVerifyOptions returns null when credentials are incomplete', () => {
  assert.equal(getYubicoVerifyOptions({ YUBICO_CLIENT_ID: '12345' }), null);
});

test('verifyRegisteredYubikeyOtp rejects invalid OTP format before other checks', async () => {
  let remoteCalled = false;
  let markCalled = false;

  const result = await verifyRegisteredYubikeyOtp({
    otp: 'invalid',
    config: { keys: ['cccccccccccc'], nfc: false },
    env: { YUBICO_CLIENT_ID: '12345', YUBICO_SECRET_KEY: 'secret' },
    markOtpUsed: async () => {
      markCalled = true;
      return true;
    },
    verifyOtp: async () => {
      remoteCalled = true;
      return { ok: true, status: 'OK', publicId: 'cccccccccccc' };
    },
  });

  assert.equal(result.ok, false);
  assert.equal(result.status, 'invalid_format');
  assert.equal(result.publicId, null);
  assert.equal(remoteCalled, false);
  assert.equal(markCalled, false);
});

test('verifyRegisteredYubikeyOtp rejects an unregistered public id without calling the remote verifier', async () => {
  let remoteCalled = false;

  const result = await verifyRegisteredYubikeyOtp({
    otp: 'cccccccccccccbdefghijklnrtuvcbdefghijklnrtuv',
    config: { keys: ['dddddddddddd'], nfc: false },
    env: { YUBICO_CLIENT_ID: '12345', YUBICO_SECRET_KEY: 'secret' },
    markOtpUsed: async () => true,
    verifyOtp: async () => {
      remoteCalled = true;
      return { ok: true, status: 'OK', publicId: 'cccccccccccc' };
    },
  });

  assert.equal(result.ok, false);
  assert.equal(result.status, 'unregistered_key');
  assert.equal(remoteCalled, false);
});

test('verifyRegisteredYubikeyOtp returns not_configured when Yubico credentials are missing', async () => {
  let remoteCalled = false;

  const result = await verifyRegisteredYubikeyOtp({
    otp: 'cccccccccccccbdefghijklnrtuvcbdefghijklnrtuv',
    config: { keys: ['cccccccccccc'], nfc: false },
    env: { YUBICO_CLIENT_ID: '12345' },
    markOtpUsed: async () => true,
    verifyOtp: async () => {
      remoteCalled = true;
      return { ok: true, status: 'OK', publicId: 'cccccccccccc' };
    },
  });

  assert.equal(result.ok, false);
  assert.equal(result.status, 'not_configured');
  assert.equal(result.publicId, 'cccccccccccc');
  assert.equal(remoteCalled, false);
});

test('verifyRegisteredYubikeyOtp returns verification_failed when remote verification fails', async () => {
  let markCalled = false;

  const result = await verifyRegisteredYubikeyOtp({
    otp: 'cccccccccccccbdefghijklnrtuvcbdefghijklnrtuv',
    config: { keys: ['cccccccccccc'], nfc: false },
    env: { YUBICO_CLIENT_ID: '12345', YUBICO_SECRET_KEY: 'secret' },
    markOtpUsed: async () => {
      markCalled = true;
      return true;
    },
    verifyOtp: async () => ({ ok: false, status: 'REPLAYED_OTP', publicId: 'cccccccccccc' }),
  });

  assert.equal(result.ok, false);
  assert.equal(result.status, 'verification_failed');
  assert.equal(result.publicId, 'cccccccccccc');
  assert.equal(markCalled, false);
});

test('verifyRegisteredYubikeyOtp returns replayed_otp when the otp was already used', async () => {
  let remoteCalled = false;
  let markCalled = false;

  const result = await verifyRegisteredYubikeyOtp({
    otp: 'cccccccccccccbdefghijklnrtuvcbdefghijklnrtuv',
    config: { keys: ['cccccccccccc'], nfc: false },
    env: { YUBICO_CLIENT_ID: '12345', YUBICO_SECRET_KEY: 'secret' },
    markOtpUsed: async () => {
      markCalled = true;
      return false;
    },
    verifyOtp: async () => {
      remoteCalled = true;
      return { ok: true, status: 'OK', publicId: 'cccccccccccc' };
    },
  });

  assert.equal(result.ok, false);
  assert.equal(result.status, 'replayed_otp');
  assert.equal(result.publicId, 'cccccccccccc');
  assert.equal(remoteCalled, true);
  assert.equal(markCalled, true);
});

test('verifyRegisteredYubikeyOtp marks the otp exactly once on success', async () => {
  const marked: string[] = [];

  const result = await verifyRegisteredYubikeyOtp({
    otp: 'cccccccccccccbdefghijklnrtuvcbdefghijklnrtuv',
    config: { keys: ['cccccccccccc'], nfc: false },
    env: { YUBICO_CLIENT_ID: '12345', YUBICO_SECRET_KEY: 'secret' },
    markOtpUsed: async (otp) => {
      marked.push(otp);
      return true;
    },
    verifyOtp: async () => ({ ok: true, status: 'OK', publicId: 'cccccccccccc' }),
  });

  assert.equal(result.ok, true);
  assert.deepEqual(marked, ['cccccccccccccbdefghijklnrtuvcbdefghijklnrtuv']);
});

test('verifyProtectedTwoFactorAccess accepts the master password before otp checks', async () => {
  let totpCalled = false;
  let yubikeyCalled = false;

  const verified = await verifyProtectedTwoFactorAccess({
    masterPasswordHash: 'master-secret',
    otp: null,
    user: {
      email: 'user@example.com',
      masterPasswordHash: 'server-hash',
      totpSecret: null,
      totpRecoveryCode: 'ABCD2345',
    },
    verifyPassword: async (candidate) => candidate === 'master-secret',
    verifyTotp: async () => {
      totpCalled = true;
      return false;
    },
    verifyYubikeyOtp: async () => {
      yubikeyCalled = true;
      return { ok: false };
    },
  });

  assert.equal(verified, true);
  assert.equal(totpCalled, false);
  assert.equal(yubikeyCalled, false);
});

test('verifyProtectedTwoFactorAccess accepts a TOTP code', async () => {
  let yubikeyCalled = false;

  const verified = await verifyProtectedTwoFactorAccess({
    masterPasswordHash: null,
    otp: '123456',
    user: {
      email: 'user@example.com',
      masterPasswordHash: 'server-hash',
      totpSecret: 'JBSWY3DPEHPK3PXP',
      totpRecoveryCode: 'ABCD2345',
    },
    verifyPassword: async () => false,
    verifyTotp: async () => true,
    verifyYubikeyOtp: async () => {
      yubikeyCalled = true;
      return { ok: false };
    },
  });

  assert.equal(verified, true);
  assert.equal(yubikeyCalled, false);
});

test('verifyProtectedTwoFactorAccess falls back to YubiKey verification', async () => {
  const verified = await verifyProtectedTwoFactorAccess({
    masterPasswordHash: null,
    otp: 'cccccccccccccbdefghijklnrtuvcbdefghijklnrtuv',
    user: {
      email: 'user@example.com',
      masterPasswordHash: 'server-hash',
      totpSecret: 'JBSWY3DPEHPK3PXP',
      totpRecoveryCode: 'ABCD2345',
    },
    verifyPassword: async () => false,
    verifyTotp: async () => false,
    verifyYubikeyOtp: async () => ({ ok: true }),
  });

  assert.equal(verified, true);
});

test('verifyProtectedTwoFactorAccess returns false for an empty otp', async () => {
  let verifyPasswordCalled = false;
  let verifyTotpCalled = false;
  let verifyYubikeyCalled = false;

  const verified = await verifyProtectedTwoFactorAccess({
    masterPasswordHash: null,
    otp: '   ',
    user: {
      email: 'user@example.com',
      masterPasswordHash: 'server-hash',
      totpSecret: 'JBSWY3DPEHPK3PXP',
      totpRecoveryCode: 'ABCD2345',
    },
    verifyPassword: async () => {
      verifyPasswordCalled = true;
      return false;
    },
    verifyTotp: async () => {
      verifyTotpCalled = true;
      return false;
    },
    verifyYubikeyOtp: async () => {
      verifyYubikeyCalled = true;
      return { ok: false };
    },
  });

  assert.equal(verified, false);
  assert.equal(verifyPasswordCalled, false);
  assert.equal(verifyTotpCalled, false);
  assert.equal(verifyYubikeyCalled, false);
});

test('verifyProtectedTwoFactorAccess accepts a recovery code when master password is absent', async () => {
  const verified = await verifyProtectedTwoFactorAccess({
    masterPasswordHash: null,
    otp: 'ABCD2345',
    user: {
      email: 'user@example.com',
      masterPasswordHash: 'server-hash',
      totpSecret: null,
      totpRecoveryCode: 'ABCD2345',
    },
    verifyPassword: async () => false,
    verifyTotp: async () => false,
    verifyYubikeyOtp: async () => ({ ok: false, status: 'not_configured', publicId: null }),
  });

  assert.equal(verified, true);
});
