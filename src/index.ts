import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Standard HTTP header Ring sends with webhook deliveries containing the HMAC-SHA256 signature.
 */
export const RING_SIGNATURE_HEADER = 'X-Signature';

export interface VerifySignatureOptions {
  /**
   * The untouched raw body string or byte buffer received over the wire.
   *
   * IMPORTANT: Never parse JSON before computing the digest! Re-serializing JSON changes
   * whitespace, property ordering, and number formatting, which invalidates the HMAC check.
   */
  readonly rawBody: string | Uint8Array | Buffer;

  /**
   * The signature header value provided by Ring (typically in `X-Signature`).
   * Can be either a hex-encoded or base64-encoded digest, with or without a `sha256=` prefix.
   */
  readonly signature: string | null | undefined;

  /**
   * The HMAC Signature Key obtained from the Ring Partner developer app dashboard.
   */
  readonly webhookSecret: string;
}

export interface VerificationResult {
  /** True if the signature is authentic and matches the raw body. */
  readonly isValid: boolean;
  /** Diagnostic error reason if verification failed. */
  readonly reason?: 'missing_signature' | 'missing_secret' | 'signature_mismatch' | 'invalid_encoding';
}

/**
 * Normalizes a signature string by stripping prefixes such as `sha256=` or whitespace.
 */
export function normalizeSignature(sig: string): string {
  const trimmed = sig.trim();
  if (trimmed.startsWith('sha256=')) {
    return trimmed.slice('sha256='.length).trim();
  }
  return trimmed;
}

/**
 * Computes an HMAC-SHA256 digest of raw request bytes using the specified secret.
 */
export function computeHmacDigest(
  rawBody: string | Uint8Array | Buffer,
  secret: string,
  encoding: 'hex' | 'base64' = 'hex'
): string {
  const hmac = createHmac('sha256', secret);
  if (typeof rawBody === 'string') {
    hmac.update(rawBody, 'utf8');
  } else {
    hmac.update(rawBody);
  }
  return hmac.digest(encoding);
}

/**
 * Constant-time comparison between two string digests.
 */
function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  return timingSafeEqual(bufA, bufB);
}

/**
 * Verifies a Ring Partner API webhook request signature against the raw body bytes.
 *
 * @example
 * ```ts
 * import { verifyRingSignature, RING_SIGNATURE_HEADER } from 'ring-webhook-verifier';
 *
 * const isValid = verifyRingSignature({
 *   rawBody: event.body, // In AWS Lambda, ensure base64 is decoded if isBase64Encoded is true
 *   signature: event.headers[RING_SIGNATURE_HEADER] ?? event.headers['x-signature'],
 *   webhookSecret: process.env.RING_WEBHOOK_SECRET!
 * });
 *
 * if (!isValid) {
 *   return { statusCode: 401, body: 'Unauthorized: signature verification failed' };
 * }
 * ```
 */
export function verifyRingSignature(options: VerifySignatureOptions): boolean {
  const result = checkRingSignature(options);
  return result.isValid;
}

/**
 * Verifies a Ring Partner API webhook signature and returns diagnostic information on failure.
 */
export function checkRingSignature(options: VerifySignatureOptions): VerificationResult {
  const { rawBody, signature, webhookSecret } = options;

  if (!webhookSecret || typeof webhookSecret !== 'string') {
    return { isValid: false, reason: 'missing_secret' };
  }

  if (!signature || typeof signature !== 'string') {
    return { isValid: false, reason: 'missing_signature' };
  }

  const cleanSig = normalizeSignature(signature);
  if (!cleanSig) {
    return { isValid: false, reason: 'missing_signature' };
  }

  // Ring typically formats digests as hex. Check hex first, then try base64 fallback.
  const expectedHex = computeHmacDigest(rawBody, webhookSecret, 'hex');
  if (secureCompare(cleanSig.toLowerCase(), expectedHex.toLowerCase())) {
    return { isValid: true };
  }

  const expectedBase64 = computeHmacDigest(rawBody, webhookSecret, 'base64');
  if (secureCompare(cleanSig, expectedBase64)) {
    return { isValid: true };
  }

  return { isValid: false, reason: 'signature_mismatch' };
}
