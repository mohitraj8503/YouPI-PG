import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import '../../../../scripts/test-support.js';
import { Database, runMigrations, MerchantRepository, PaymentSessionRepository, ObservationRepository } from '@youpi/db';
import { WebhookEngine } from '../webhook-engine.js';
import { verifyHmac } from '@youpi/common';

describe('Webhook Engine Integration Tests', () => {
  let db;
  let merchantRepo;
  let sessionRepo;
  let webhookEngine;
  let receiverServer;
  let receiverPort;
  let receivedWebhooks = [];
  let shouldReceiverFail = false;

  before(async () => {
    db = new Database({ inMemory: true });
    runMigrations(db);
    merchantRepo = new MerchantRepository(db);
    sessionRepo = new PaymentSessionRepository(db);

    webhookEngine = new WebhookEngine({
      db,
      merchantRepo,
      maxRetries: 3
    });

    // Start a mock merchant webhook receiver HTTP server
    receiverServer = http.createServer((req, res) => {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        receivedWebhooks.push({
          headers: req.headers,
          body: JSON.parse(body || '{}')
        });

        if (shouldReceiverFail) {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('Internal Merchant Error');
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ received: true }));
        }
      });
    });

    await new Promise(resolve => {
      receiverServer.listen(0, () => {
        receiverPort = receiverServer.address().port;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise(cb => receiverServer.close(cb));
    db.close();
  });

  test('successfully dispatches HMAC-SHA256 signed webhook on payment event', async () => {
    const merchant = merchantRepo.create({
      businessName: 'Webhook Test Store',
      slug: 'webhook-store',
      contactEmail: 'store@example.com',
      contactPhone: '9876543210',
      webhookUrl: `http://localhost:${receiverPort}/webhook`,
      webhookSecret: 'test_secret_for_merchant_signatures_123'
    });

    const session = sessionRepo.create({
      merchantId: merchant.id,
      orderId: 'HOOK-ORD-001',
      amountPaise: 20000n
    });

    receivedWebhooks = [];
    shouldReceiverFail = false;

    const result = await webhookEngine.dispatch('SUCCESS', session);

    assert.equal(result.delivered, true);
    assert.equal(result.status, 200);
    assert.ok(result.deliveryId);

    // Verify received payload & signature
    assert.equal(receivedWebhooks.length, 1);
    const hook = receivedWebhooks[0];

    assert.equal(hook.headers['x-gateway-event'], 'SUCCESS');
    assert.ok(hook.headers['x-gateway-signature'].startsWith('sha256='));
    assert.equal(hook.headers['x-gateway-delivery-id'], result.deliveryId);

    assert.equal(hook.body.event, 'SUCCESS');
    assert.equal(hook.body.orderId, 'HOOK-ORD-001');
    assert.equal(hook.body.amount, '200.00');
    assert.equal(hook.body.amountPaise, 20000);

    // Cryptographically verify signature using merchant webhookSecret
    const rawSig = hook.headers['x-gateway-signature'].replace('sha256=', '');
    const isValid = verifyHmac(JSON.stringify(hook.body), merchant.webhookSecret, rawSig);
    assert.equal(isValid, true);
    assert.ok('utr' in hook.body);

    // Verify recorded in DB as successful
    const delivery = db.queryOne('SELECT * FROM webhook_deliveries WHERE id = ?', [result.deliveryId]);
    assert.ok(delivery);
    assert.equal(delivery.is_successful, 1);
    assert.equal(delivery.response_status, 200);
  });

  test('persists the delivery intent before the webhook request is sent', async () => {
    const merchant = merchantRepo.create({
      businessName: 'Intent Store',
      slug: 'intent-store',
      contactEmail: 'intent@example.com',
      contactPhone: '9876543210',
      webhookUrl: `http://localhost:${receiverPort}/webhook-intent`,
      webhookSecret: 'test_secret_for_intent_store_123'
    });

    const session = sessionRepo.create({
      merchantId: merchant.id,
      orderId: 'HOOK-ORD-INTENT',
      amountPaise: 15000n
    });

    // Inspect the database at the moment the request leaves, which is the only point where
    // "persisted before send" is observable.
    const realFetch = globalThis.fetch;
    let rowDuringSend = null;
    let bodyDuringSend = null;
    let deliveryIdDuringSend = null;

    globalThis.fetch = async (url, init) => {
      bodyDuringSend = init.body;
      deliveryIdDuringSend = init.headers['X-Gateway-Delivery-Id'];
      rowDuringSend = db.queryOne('SELECT * FROM webhook_deliveries WHERE id = ?', [deliveryIdDuringSend]);
      return { ok: true, status: 200, text: async () => '{"received":true}' };
    };

    let result;
    try {
      result = await webhookEngine.dispatch('SUCCESS', session);
    } finally {
      globalThis.fetch = realFetch;
    }

    assert.equal(result.delivered, true);
    assert.ok(rowDuringSend, 'the delivery intent must exist before the webhook is sent');
    assert.equal(rowDuringSend.id, deliveryIdDuringSend);
    assert.equal(rowDuringSend.payload, bodyDuringSend, 'the persisted body must be the body that was sent');
    assert.equal(rowDuringSend.event_type, 'SUCCESS');
    assert.equal(rowDuringSend.endpoint_url, merchant.webhookUrl);
    assert.equal(rowDuringSend.attempt_count, 1);
    assert.equal(rowDuringSend.is_successful, 0);
    assert.ok(rowDuringSend.next_retry_at, 'an unrecorded delivery must be scheduled for a retry');

    // The outcome is recorded against that same row, not a second one.
    const rows = db.query('SELECT * FROM webhook_deliveries WHERE payment_id = ?', [session.id]);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].is_successful, 1);
    assert.equal(rows[0].response_status, 200);
    assert.equal(rows[0].next_retry_at, null);
  });

  test('finishes a dispatch interrupted before its outcome was recorded', async () => {
    const merchant = merchantRepo.create({
      businessName: 'Interrupted Store',
      slug: 'interrupted-store',
      contactEmail: 'interrupted@example.com',
      contactPhone: '9876543210',
      webhookUrl: `http://localhost:${receiverPort}/webhook-interrupted`,
      webhookSecret: 'test_secret_for_interrupted_store_123'
    });

    const session = sessionRepo.create({
      merchantId: merchant.id,
      orderId: 'HOOK-ORD-INTERRUPTED',
      amountPaise: 30000n
    });

    receivedWebhooks = [];
    shouldReceiverFail = false;

    // Simulate the process dying after the merchant received the webhook but before the
    // outcome was written back: the send succeeds, the settle step throws.
    const realExecute = db.execute.bind(db);
    db.execute = (sql, params) => {
      if (String(sql).includes('UPDATE webhook_deliveries')) {
        throw new Error('simulated process death before the outcome was recorded');
      }
      return realExecute(sql, params);
    };

    try {
      await assert.rejects(
        () => webhookEngine.dispatch('SUCCESS', session),
        /simulated process death/
      );
    } finally {
      db.execute = realExecute;
    }

    const interrupted = db.queryOne('SELECT * FROM webhook_deliveries WHERE payment_id = ?', [session.id]);
    assert.ok(interrupted, 'the interrupted delivery must survive as a pending record');
    assert.equal(interrupted.is_successful, 0);
    assert.equal(interrupted.response_status, null);
    assert.equal(receivedWebhooks.length, 1, 'the first attempt did reach the merchant');

    // Once the claim lock has elapsed the retry worker owns the delivery and completes it.
    db.execute('UPDATE webhook_deliveries SET next_retry_at = ? WHERE id = ?', [
      new Date(Date.now() - 60000).toISOString(), interrupted.id
    ]);
    const retryResults = await webhookEngine.retryPending();
    assert.equal(retryResults.length, 1);
    assert.equal(retryResults[0].success, true);

    const retried = receivedWebhooks[receivedWebhooks.length - 1];
    assert.equal(retried.headers['x-gateway-delivery-id'], interrupted.id,
      'a recovered delivery keeps its delivery id so the merchant can deduplicate it');
    assert.equal(retried.body.event, 'SUCCESS');
    assert.equal(retried.body.orderId, 'HOOK-ORD-INTERRUPTED');
    const retrySig = retried.headers['x-gateway-signature'].replace('sha256=', '');
    assert.equal(verifyHmac(JSON.stringify(retried.body), merchant.webhookSecret, retrySig), true);

    const settled = db.queryOne('SELECT * FROM webhook_deliveries WHERE id = ?', [interrupted.id]);
    assert.equal(settled.is_successful, 1);
    assert.equal(settled.attempt_count, 2);
  });

  test('carries the bank reference (UTR) from the attributed observation', async () => {
    const merchant = merchantRepo.create({
      businessName: 'UTR Store',
      slug: 'utr-store',
      contactEmail: 'utr@example.com',
      contactPhone: '9876543210',
      webhookUrl: `http://localhost:${receiverPort}/webhook-utr`,
      webhookSecret: 'test_secret_for_utr_signatures_123'
    });

    const session = sessionRepo.create({
      merchantId: merchant.id,
      orderId: 'HOOK-ORD-UTR',
      amountPaise: 20000n,
      receivingAccountId: '00000000-0000-0000-0000-000000000002'
    });

    // The UTR lives on the observation, not on the session row.
    const observation = new ObservationRepository(db).create({
      receivingAccountId: session.receivingAccountId,
      source: 'GOOGLE_MESSAGES',
      rawText: 'Rs 200.00 credited UPI ref 412345678901',
      amountPaise: 20000n,
      bankReferenceNumber: '412345678901',
      observedAt: new Date(),
      fingerprintHash: 'fp_utr_test'
    });
    db.execute('UPDATE payment_sessions SET attributed_observation_id = ? WHERE id = ?', [observation.id, session.id]);

    receivedWebhooks = [];
    shouldReceiverFail = false;

    const result = await webhookEngine.dispatch('SUCCESS', sessionRepo.findById(session.id));
    assert.equal(result.delivered, true);

    const hook = receivedWebhooks.find(h => h.body.orderId === 'HOOK-ORD-UTR');
    assert.ok(hook, 'webhook not received');
    assert.equal(hook.body.utr, '412345678901');

    // The signature must still cover the body that now includes the UTR.
    const rawSig = hook.headers['x-gateway-signature'].replace('sha256=', '');
    assert.equal(verifyHmac(JSON.stringify(hook.body), merchant.webhookSecret, rawSig), true);

    // The documented webhook contract must expose every field.
    for (const field of ['event', 'paymentId', 'orderId', 'amount', 'amountPaise', 'currency', 'method', 'utr', 'completedAt', 'metadata']) {
      assert.ok(field in hook.body, `missing documented webhook field: ${field}`);
    }
  });

  test('records failure and supports retry on merchant HTTP 500 error', async () => {
    const merchant = merchantRepo.create({
      businessName: 'Failing Store',
      slug: 'failing-store',
      contactEmail: 'fail@example.com',
      contactPhone: '9876543210',
      webhookUrl: `http://localhost:${receiverPort}/webhook-fail`,
      webhookSecret: 'secret_abc_123'
    });

    const session = sessionRepo.create({
      merchantId: merchant.id,
      orderId: 'HOOK-ORD-FAIL',
      amountPaise: 50000n
    });

    shouldReceiverFail = true;
    const result = await webhookEngine.dispatch('FAILED', session);

    assert.equal(result.delivered, false);
    assert.equal(result.status, 500);

    // Verify recorded as failed with next_retry_at set
    const delivery = db.queryOne('SELECT * FROM webhook_deliveries WHERE id = ?', [result.deliveryId]);
    assert.equal(delivery.is_successful, 0);
    assert.equal(delivery.attempt_count, 1);
    assert.ok(delivery.next_retry_at);

    // Now make receiver healthy and simulate retry worker
    shouldReceiverFail = false;
    const pastIso = new Date(Date.now() - 60000).toISOString();
    db.execute('UPDATE webhook_deliveries SET next_retry_at = ? WHERE id = ?', [pastIso, result.deliveryId]);

    const retryResults = await webhookEngine.retryPending();
    assert.equal(retryResults.length, 1);
    assert.equal(retryResults[0].success, true);
    assert.equal(retryResults[0].attempt, 2);

    const updatedDelivery = db.queryOne('SELECT * FROM webhook_deliveries WHERE id = ?', [result.deliveryId]);
    assert.equal(updatedDelivery.is_successful, 1);

    // A retried delivery must carry the SAME MAC as a first delivery: the signature covers
    // the exact transmitted body, so the merchant's verification accepts it too. Signing the
    // retry as `${timestamp}.${payload}` made every retry fail verification.
    const retried = receivedWebhooks.filter(h => h.body && h.body.orderId === 'HOOK-ORD-FAIL').pop();
    assert.ok(retried, 'retried webhook not received');
    const retrySig = retried.headers['x-gateway-signature'].replace('sha256=', '');
    assert.equal(verifyHmac(JSON.stringify(retried.body), merchant.webhookSecret, retrySig), true);
  });

  test('a retried delivery keeps the timestamp and delivery id of the original body', async () => {
    const merchant = merchantRepo.create({
      businessName: 'Retry Consistency Store',
      slug: 'retry-consistency-store',
      contactEmail: 'retry@example.com',
      contactPhone: '9876543210',
      webhookUrl: `http://localhost:${receiverPort}/webhook-retry-consistency`,
      webhookSecret: 'test_secret_for_retry_consistency_123'
    });

    const session = sessionRepo.create({
      merchantId: merchant.id,
      orderId: 'HOOK-ORD-RETRY-CONSISTENCY',
      amountPaise: 70000n
    });

    receivedWebhooks = [];
    shouldReceiverFail = false;

    const result = await webhookEngine.dispatch('SUCCESS', session);
    assert.equal(result.delivered, true);
    const first = receivedWebhooks[receivedWebhooks.length - 1];
    const firstBody = first.body;
    assert.ok(firstBody.timestamp, 'payload must carry a timestamp');
    assert.ok(firstBody.deliveryId, 'payload must carry a delivery id');

    // The retry resends the SAME body, so the headers must describe that same body.
    db.execute('UPDATE webhook_deliveries SET next_retry_at = ? WHERE id = ?', [
      new Date(Date.now() - 60000).toISOString(), result.deliveryId
    ]);
    await webhookEngine.retryPending();

    const retried = receivedWebhooks[receivedWebhooks.length - 1];
    assert.equal(String(retried.headers['x-gateway-timestamp']), String(firstBody.timestamp),
      'a retry must not recompute the timestamp, or it disagrees with the signed body');
    assert.equal(String(retried.headers['x-gateway-delivery-id']), String(firstBody.deliveryId),
      'a retry must keep the delivery id of the body it resends');
    assert.equal(JSON.stringify(retried.body), JSON.stringify(first.body), 'a retry must resend the identical body');

    // And the merchant's verifier must accept the retried delivery.
    const rawSig = retried.headers['x-gateway-signature'].replace('sha256=', '');
    assert.equal(verifyHmac(JSON.stringify(retried.body), merchant.webhookSecret, rawSig), true);
  });

  test('persists delivery failure record when merchant webhookSecret is missing', async () => {
    const merchantNoSecret = merchantRepo.create({
      businessName: 'No Secret Store',
      slug: 'no-secret-store',
      contactEmail: 'nosecret@example.com',
      contactPhone: '9876543210',
      webhookUrl: `http://localhost:${receiverPort}/webhook-no-secret`,
      webhookSecret: 'temp_secret'
    });
    // Explicitly set secret to empty string in DB to test missing secret guard
    db.execute("UPDATE merchants SET webhook_secret = '' WHERE id = ?", [merchantNoSecret.id]);

    const session = sessionRepo.create({
      merchantId: merchantNoSecret.id,
      orderId: 'HOOK-ORD-NO-SEC',
      amountPaise: 10000n
    });

    const res = await webhookEngine.dispatch('SUCCESS', session);
    assert.equal(res.delivered, false);
    assert.equal(res.status, 500);
    assert.ok(res.deliveryId);

    const recorded = db.queryOne('SELECT * FROM webhook_deliveries WHERE id = ?', [res.deliveryId]);
    assert.ok(recorded);
    assert.equal(recorded.is_successful, 0);
    assert.equal(recorded.response_status, 500);
    assert.match(recorded.response_body, /webhookSecret is not configured/);
  });
});
