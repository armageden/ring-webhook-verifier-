# ring-webhook-verifier

> Zero-dependency Node.js utility to safely verify Ring Partner API webhook HMAC-SHA256 signatures (`X-Signature`) without JSON whitespace or key-ordering corruption.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node: >=18](https://img.shields.io/badge/Node->=18-brightgreen.svg)]()

Created as an open-source companion utility for the **Amazon Developer Hackathon 2026** (Ring and Fire TV tracks).

---

## The Problem

Ring webhook security relies on an HMAC-SHA256 digest sent in the `X-Signature` header. The HMAC is computed over the **exact, untouched raw body bytes** sent by Ring's webhook servers.

A common pitfall in serverless runtimes (AWS Lambda, Express, Next.js, Fastify):

```ts
// ❌ WRONG: Parsing JSON before verification
const body = JSON.parse(event.body);
const digest = crypto.createHmac('sha256', secret).update(JSON.stringify(body)).digest('hex');
// Result: 100% of webhook requests FAIL verification!
// Why? JSON.stringify alters whitespace, property ordering, and number formatting.
```

`ring-webhook-verifier` solves this with zero dependencies, constant-time comparison (`crypto.timingSafeEqual`) to prevent timing attacks, and built-in normalization for both hex and base64 digest formats.

---

## Installation

```bash
npm install ring-webhook-verifier
```

*(Or copy `src/index.ts` directly into your project if you prefer zero runtime dependencies).*

---

## Usage

### In AWS Lambda (API Gateway HTTP API v2 / SAM)

```typescript
import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { verifyRingSignature, RING_SIGNATURE_HEADER } from 'ring-webhook-verifier';

export async function handler(event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2> {
  // 1. Decode raw body if API Gateway base64-encoded it
  const rawBody = event.isBase64Encoded && event.body
    ? Buffer.from(event.body, 'base64').toString('utf8')
    : (event.body ?? '');

  // 2. Extract signature header (case-insensitive lookup)
  const signature = event.headers[RING_SIGNATURE_HEADER] ?? event.headers['x-signature'];

  // 3. Verify signature BEFORE parsing JSON
  const isValid = verifyRingSignature({
    rawBody,
    signature,
    webhookSecret: process.env.RING_WEBHOOK_SECRET!
  });

  if (!isValid) {
    // Ring treats 4xx as permanent failure — essential for rejecting forgeries immediately
    return {
      statusCode: 401,
      body: JSON.stringify({ error: 'Invalid HMAC signature' })
    };
  }

  // 4. Safe to parse now
  const payload = JSON.parse(rawBody);
  console.log('Received authentic Ring event:', payload.event_type);

  return { statusCode: 200, body: JSON.stringify({ received: true }) };
}
```

### With Diagnostic Reasons

```typescript
import { checkRingSignature } from 'ring-webhook-verifier';

const result = checkRingSignature({
  rawBody: req.rawBody,
  signature: req.headers['x-signature'],
  webhookSecret: process.env.RING_WEBHOOK_SECRET!
});

if (!result.isValid) {
  console.warn(`Verification failed: ${result.reason}`); 
  // 'missing_signature' | 'missing_secret' | 'signature_mismatch'
}
```

---

## Features

- **Zero External Dependencies:** Built solely on native Node.js `node:crypto`.
- **Timing-Attack Safe:** Uses `crypto.timingSafeEqual` for all digest comparisons.
- **Buffer & String Agnostic:** Accepts `string`, `Buffer`, or `Uint8Array`.
- **Prefix Permissive:** Gracefully handles signatures formatted as `sha256=<hash>` or raw hex/base64 strings.
- **Strict TypeScript:** Ships with full TypeScript definitions and strict null-checks.

---

## License

MIT © 2026 farhan
