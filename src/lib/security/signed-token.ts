import { createHmac, timingSafeEqual } from 'node:crypto';

export interface SignedTokenPayload {
  pactId: string;
  verifierId: string;
  action: 'approve' | 'reject' | 'attest';
  expiresAtIso: string;
  customData?: Record<string, unknown>;
}

export interface VerificationResult {
  isValid: boolean;
  isExpired: boolean;
  payload: SignedTokenPayload | null;
  error: string | null;
}

const MIN_SECRET_LENGTH = 16;

/**
 * Validates that secretKey is at least 16 characters long.
 * Throws an Error if too weak.
 */
function validateSecretKey(secretKey: string): void {
  if (!secretKey || typeof secretKey !== 'string' || secretKey.length < MIN_SECRET_LENGTH) {
    throw new Error(
      `Secret key must be at least ${MIN_SECRET_LENGTH} characters long.`
    );
  }
}

/**
 * Generates a URL-safe HMAC-SHA256 signed verification token.
 * Output format: `${payloadBase64Url}.${signatureBase64Url}`
 */
export function generateSignedToken(
  payload: SignedTokenPayload,
  secretKey: string
): string {
  validateSecretKey(secretKey);

  if (!payload || typeof payload !== 'object') {
    throw new Error('Payload must be a valid SignedTokenPayload object.');
  }

  // 1. Serialize payload to JSON and encode to URL-safe base64
  const serializedPayload = JSON.stringify(payload);
  const payloadB64Url = Buffer.from(serializedPayload, 'utf-8').toString('base64url');

  // 2. Compute HMAC-SHA256 signature in URL-safe base64
  const signatureB64Url = createHmac('sha256', secretKey)
    .update(payloadB64Url)
    .digest('base64url');

  // 3. Return composite token
  return `${payloadB64Url}.${signatureB64Url}`;
}

/**
 * Verifies a URL-safe HMAC-SHA256 signed token.
 * Uses constant-time buffer comparison (crypto.timingSafeEqual) to prevent timing attacks.
 */
export function verifySignedToken(
  token: string,
  secretKey: string,
  nowClockIso?: string
): VerificationResult {
  validateSecretKey(secretKey);

  if (!token || typeof token !== 'string') {
    return {
      isValid: false,
      isExpired: false,
      payload: null,
      error: 'Token must be a non-empty string.',
    };
  }

  const parts = token.split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return {
      isValid: false,
      isExpired: false,
      payload: null,
      error: 'Malformed token: expected format <payload>.<signature>.',
    };
  }

  const [payloadB64Url, signatureB64Url] = parts;

  // Recompute HMAC-SHA256 over payload segment
  const expectedSigBuffer = createHmac('sha256', secretKey)
    .update(payloadB64Url)
    .digest();

  let providedSigBuffer: Buffer;
  try {
    providedSigBuffer = Buffer.from(signatureB64Url, 'base64url');
  } catch {
    return {
      isValid: false,
      isExpired: false,
      payload: null,
      error: 'Invalid signature encoding.',
    };
  }

  // timingSafeEqual requires buffers of identical length
  if (expectedSigBuffer.length !== providedSigBuffer.length) {
    return {
      isValid: false,
      isExpired: false,
      payload: null,
      error: 'Invalid token signature.',
    };
  }

  const isSignatureMatch = timingSafeEqual(expectedSigBuffer, providedSigBuffer);
  if (!isSignatureMatch) {
    return {
      isValid: false,
      isExpired: false,
      payload: null,
      error: 'Invalid token signature.',
    };
  }

  // Decode and parse the JSON payload
  let payload: SignedTokenPayload;
  try {
    const rawPayloadJson = Buffer.from(payloadB64Url, 'base64url').toString('utf-8');
    payload = JSON.parse(rawPayloadJson) as SignedTokenPayload;
  } catch {
    return {
      isValid: false,
      isExpired: false,
      payload: null,
      error: 'Failed to decode or parse token payload.',
    };
  }

  // Validate required payload properties
  if (!payload.pactId || !payload.verifierId || !payload.action || !payload.expiresAtIso) {
    return {
      isValid: false,
      isExpired: false,
      payload: null,
      error: 'Missing required payload properties.',
    };
  }

  // Validate expiration
  const now = nowClockIso ? new Date(nowClockIso) : new Date();
  const expiresAt = new Date(payload.expiresAtIso);

  if (isNaN(expiresAt.getTime())) {
    return {
      isValid: false,
      isExpired: false,
      payload: null,
      error: 'Invalid expiresAtIso date format.',
    };
  }

  if (expiresAt.getTime() <= now.getTime()) {
    return {
      isValid: false,
      isExpired: true,
      payload,
      error: 'Token has expired.',
    };
  }

  return {
    isValid: true,
    isExpired: false,
    payload,
    error: null,
  };
}
