import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateSignedToken,
  verifySignedToken,
  type SignedTokenPayload,
} from '../src/lib/security/signed-token';

describe('HMAC-SHA256 Signed Verification Token Generator (signed-token.ts)', () => {
  const validSecret = 'super-secure-verification-secret-key-32chars!';
  const weakSecret = 'too-short';

  const mockPayload: SignedTokenPayload = {
    pactId: 'pact-uuid-1234-abcd',
    verifierId: 'user-verifier-9988',
    action: 'approve',
    expiresAtIso: '2027-01-01T00:00:00.000Z',
    customData: { note: 'Accountability milestone verified' },
  };

  it('generates a URL-safe composite token format <payload>.<signature>', () => {
    const token = generateSignedToken(mockPayload, validSecret);
    assert.ok(token);
    assert.strictEqual(typeof token, 'string');

    const parts = token.split('.');
    assert.strictEqual(parts.length, 2);
    assert.ok(parts[0].length > 0);
    assert.ok(parts[1].length > 0);
  });

  it('verifies a valid token successfully with expected payload', () => {
    const token = generateSignedToken(mockPayload, validSecret);
    const result = verifySignedToken(token, validSecret, '2026-11-23T00:00:00.000Z');

    assert.strictEqual(result.isValid, true);
    assert.strictEqual(result.isExpired, false);
    assert.strictEqual(result.error, null);
    assert.deepStrictEqual(result.payload, mockPayload);
  });

  it('rejects verification if any character in payload is tampered with', () => {
    const token = generateSignedToken(mockPayload, validSecret);
    const [payloadB64, sigB64] = token.split('.');

    const decoded = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8'));
    decoded.action = 'reject'; // Tampering action
    const tamperedPayloadB64 = Buffer.from(JSON.stringify(decoded), 'utf-8').toString('base64url');

    const tamperedToken = `${tamperedPayloadB64}.${sigB64}`;
    const result = verifySignedToken(tamperedToken, validSecret);

    assert.strictEqual(result.isValid, false);
    assert.strictEqual(result.payload, null);
    assert.strictEqual(result.error, 'Invalid token signature.');
  });

  it('rejects verification if signature is tampered with', () => {
    const token = generateSignedToken(mockPayload, validSecret);
    const [payloadB64, sigB64] = token.split('.');

    const tamperedSig = sigB64.slice(0, -1) + (sigB64.endsWith('a') ? 'b' : 'a');
    const tamperedToken = `${payloadB64}.${tamperedSig}`;

    const result = verifySignedToken(tamperedToken, validSecret);
    assert.strictEqual(result.isValid, false);
    assert.strictEqual(result.payload, null);
    assert.strictEqual(result.error, 'Invalid token signature.');
  });

  it('returns isValid: false and isExpired: true for expired tokens', () => {
    const expiredPayload: SignedTokenPayload = {
      ...mockPayload,
      expiresAtIso: '2026-10-01T00:00:00.000Z',
    };

    const token = generateSignedToken(expiredPayload, validSecret);
    const result = verifySignedToken(token, validSecret, '2026-11-23T00:00:00.000Z');

    assert.strictEqual(result.isValid, false);
    assert.strictEqual(result.isExpired, true);
    assert.strictEqual(result.error, 'Token has expired.');
    assert.strictEqual(result.payload?.pactId, expiredPayload.pactId);
  });

  it('throws descriptive validation error for weak secret keys (< 16 characters)', () => {
    assert.throws(
      () => generateSignedToken(mockPayload, weakSecret),
      /Secret key must be at least 16 characters long/
    );

    const token = generateSignedToken(mockPayload, validSecret);
    assert.throws(
      () => verifySignedToken(token, weakSecret),
      /Secret key must be at least 16 characters long/
    );
  });

  it('protects against malformed token inputs gracefully', () => {
    assert.strictEqual(verifySignedToken('', validSecret).isValid, false);
    assert.strictEqual(verifySignedToken('no-dot-token', validSecret).isValid, false);
    assert.strictEqual(verifySignedToken('part1.part2.part3', validSecret).isValid, false);
  });
});
