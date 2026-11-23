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
const ALLOWED_ACTIONS: ReadonlySet<string> = new Set(['approve', 'reject', 'attest']);

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
 * Validates that an ISO date string matches standard ISO 8601 format
 * and represents a real calendar date (rejecting impossible dates like Feb 30).
 */
export function isValidCalendarIsoString(dateStr: string): boolean {
  if (typeof dateStr !== 'string') return false;

  // Match ISO 8601: YYYY-MM-DDTHH:mm:ss(.sss)?(Z|[+-]HH:mm)? or YYYY-MM-DD
  const regex = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:Z|([+-])(\d{2})(?::?(\d{2}))?)?)?$/i;
  const match = dateStr.match(regex);
  if (!match) return false;

  const year = parseInt(match[1], 10);
  const month = parseInt(match[2], 10);
  const day = parseInt(match[3], 10);

  if (month < 1 || month > 12) return false;

  // Days in month validation (accounting for leap years)
  const isLeapYear = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const daysInMonth = [31, isLeapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

  if (day < 1 || day > daysInMonth[month - 1]) return false;

  // If time component is present, validate hours, minutes, seconds
  if (match[4] !== undefined) {
    const hours = parseInt(match[4], 10);
    const minutes = parseInt(match[5], 10);
    const seconds = parseInt(match[6], 10);

    if (hours < 0 || hours > 23) return false;
    if (minutes < 0 || minutes > 59) return false;
    if (seconds < 0 || seconds > 59) return false;

    // Validate timezone offset if present
    if (match[9] !== undefined) {
      const tzHours = parseInt(match[9], 10);
      const tzMinutes = match[10] !== undefined ? parseInt(match[10], 10) : 0;
      if (tzHours < 0 || tzHours > 23 || tzMinutes < 0 || tzMinutes > 59) return false;
    }
  }

  const d = new Date(dateStr);
  return !isNaN(d.getTime());
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

  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('Payload must be a non-null SignedTokenPayload object.');
  }

  if (typeof payload.pactId !== 'string' || payload.pactId.trim() === '') {
    throw new Error('pactId must be a non-empty string.');
  }

  if (typeof payload.verifierId !== 'string' || payload.verifierId.trim() === '') {
    throw new Error('verifierId must be a non-empty string.');
  }

  if (typeof payload.action !== 'string' || !ALLOWED_ACTIONS.has(payload.action)) {
    throw new Error('action must be one of "approve", "reject", or "attest".');
  }

  if (typeof payload.expiresAtIso !== 'string' || !isValidCalendarIsoString(payload.expiresAtIso)) {
    throw new Error('expiresAtIso must be a valid calendar ISO date string.');
  }

  if (payload.customData !== undefined) {
    if (
      typeof payload.customData !== 'object' ||
      payload.customData === null ||
      Array.isArray(payload.customData)
    ) {
      throw new Error('customData must be a record object.');
    }
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
  let rawPayload: unknown;
  try {
    const rawPayloadJson = Buffer.from(payloadB64Url, 'base64url').toString('utf-8');
    rawPayload = JSON.parse(rawPayloadJson);
  } catch {
    return {
      isValid: false,
      isExpired: false,
      payload: null,
      error: 'Failed to decode or parse token payload.',
    };
  }

  // Reject null, arrays, and other non-object values
  if (!rawPayload || typeof rawPayload !== 'object' || Array.isArray(rawPayload)) {
    return {
      isValid: false,
      isExpired: false,
      payload: null,
      error: 'Invalid token payload: expected a non-null object.',
    };
  }

  const payloadObj = rawPayload as Record<string, unknown>;

  // Require non-empty string pactId and verifierId
  if (typeof payloadObj.pactId !== 'string' || payloadObj.pactId.trim() === '') {
    return {
      isValid: false,
      isExpired: false,
      payload: null,
      error: 'Missing or invalid pactId property: expected non-empty string.',
    };
  }

  if (typeof payloadObj.verifierId !== 'string' || payloadObj.verifierId.trim() === '') {
    return {
      isValid: false,
      isExpired: false,
      payload: null,
      error: 'Missing or invalid verifierId property: expected non-empty string.',
    };
  }

  // Require action to be 'approve' | 'reject' | 'attest'
  if (typeof payloadObj.action !== 'string' || !ALLOWED_ACTIONS.has(payloadObj.action)) {
    return {
      isValid: false,
      isExpired: false,
      payload: null,
      error: 'Missing or invalid action property: must be "approve", "reject", or "attest".',
    };
  }

  // Require string expiresAtIso
  if (typeof payloadObj.expiresAtIso !== 'string' || payloadObj.expiresAtIso.trim() === '') {
    return {
      isValid: false,
      isExpired: false,
      payload: null,
      error: 'Missing or invalid expiresAtIso property: expected non-empty string.',
    };
  }

  // Validate customData when present
  if (payloadObj.customData !== undefined) {
    if (
      typeof payloadObj.customData !== 'object' ||
      payloadObj.customData === null ||
      Array.isArray(payloadObj.customData)
    ) {
      return {
        isValid: false,
        isExpired: false,
        payload: null,
        error: 'Invalid customData: must be a record object.',
      };
    }
  }

  const payload: SignedTokenPayload = {
    pactId: payloadObj.pactId,
    verifierId: payloadObj.verifierId,
    action: payloadObj.action as SignedTokenPayload['action'],
    expiresAtIso: payloadObj.expiresAtIso,
    ...(payloadObj.customData !== undefined
      ? { customData: payloadObj.customData as Record<string, unknown> }
      : {}),
  };

  // Clock validation
  let now: Date;
  if (nowClockIso !== undefined) {
    if (typeof nowClockIso !== 'string' || !isValidCalendarIsoString(nowClockIso)) {
      return {
        isValid: false,
        isExpired: false,
        payload: null,
        error: 'Invalid nowClockIso date format.',
      };
    }
    now = new Date(nowClockIso);
  } else {
    now = new Date();
  }

  // Expiration validation with calendar correctness
  if (!isValidCalendarIsoString(payload.expiresAtIso)) {
    return {
      isValid: false,
      isExpired: false,
      payload: null,
      error: 'Invalid expiresAtIso date format.',
    };
  }

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
