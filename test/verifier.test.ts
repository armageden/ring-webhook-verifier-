import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  verifyRingSignature,
  checkRingSignature,
  computeHmacDigest,
  normalizeSignature,
  RING_SIGNATURE_HEADER
} from '../src/index.js';

describe('ring-webhook-verifier', () => {
  const secret = 'super_secret_ring_key_12345';
  const samplePayload = JSON.stringify({
    event_type: 'motion_detected',
    data: {
      attributes: {
        source: 'front_door_cam',
        sub_type: 'human',
        timestamp: 1727500000000
      }
    }
  });

  it('exports the standard header constant', () => {
    assert.equal(RING_SIGNATURE_HEADER, 'X-Signature');
  });

  it('validates authentic hex signatures', () => {
    const validHex = computeHmacDigest(samplePayload, secret, 'hex');
    assert.equal(
      verifyRingSignature({ rawBody: samplePayload, signature: validHex, webhookSecret: secret }),
      true
    );
  });

  it('validates signatures with sha256= prefix', () => {
    const validHex = computeHmacDigest(samplePayload, secret, 'hex');
    assert.equal(
      verifyRingSignature({ rawBody: samplePayload, signature: `sha256=${validHex}`, webhookSecret: secret }),
      true
    );
  });

  it('validates authentic base64 signatures', () => {
    const validBase64 = computeHmacDigest(samplePayload, secret, 'base64');
    assert.equal(
      verifyRingSignature({ rawBody: samplePayload, signature: validBase64, webhookSecret: secret }),
      true
    );
  });

  it('rejects tampered bodies', () => {
    const validHex = computeHmacDigest(samplePayload, secret, 'hex');
    const tamperedPayload = samplePayload.replace('human', 'vehicle');
    assert.equal(
      verifyRingSignature({ rawBody: tamperedPayload, signature: validHex, webhookSecret: secret }),
      false
    );
    const result = checkRingSignature({ rawBody: tamperedPayload, signature: validHex, webhookSecret: secret });
    assert.equal(result.isValid, false);
    assert.equal(result.reason, 'signature_mismatch');
  });

  it('rejects missing or empty signatures', () => {
    assert.equal(
      verifyRingSignature({ rawBody: samplePayload, signature: '', webhookSecret: secret }),
      false
    );
    const result = checkRingSignature({ rawBody: samplePayload, signature: null, webhookSecret: secret });
    assert.equal(result.isValid, false);
    assert.equal(result.reason, 'missing_signature');
  });

  it('rejects missing secrets', () => {
    const validHex = computeHmacDigest(samplePayload, secret, 'hex');
    const result = checkRingSignature({ rawBody: samplePayload, signature: validHex, webhookSecret: '' });
    assert.equal(result.isValid, false);
    assert.equal(result.reason, 'missing_secret');
  });

  it('handles Buffer and Uint8Array inputs identically to strings', () => {
    const buf = Buffer.from(samplePayload, 'utf8');
    const validHex = computeHmacDigest(samplePayload, secret, 'hex');
    assert.equal(
      verifyRingSignature({ rawBody: buf, signature: validHex, webhookSecret: secret }),
      true
    );
  });
});
