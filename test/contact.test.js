"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { submitLead, TO, DEFAULT_FROM } = require("../lib/contact");

const TOKEN = "a".repeat(32);

function base(overrides = {}) {
  return {
    csrf: TOKEN,
    cookie: TOKEN,
    website: "",
    name: "Test Lead",
    email: "test@example.com",
    domain: "ten-percent.co.uk",
    host: "SiteGround",
    message: "Please quote",
    php: "8.3.35",
    verdict: "vulnerable",
    ip: "127.0.0.1",
    ua: "curl/8.9.1",
    ...overrides,
  };
}

describe("quote email", () => {
  it("sends the lead shape to Marc via Resend", async () => {
    const calls = [];
    const result = await submitLead(base(), {
      env: { RESEND_API_KEY: "re_test" },
      clock: () => new Date("2026-10-24T23:41:40.000Z"),
      fetchImpl: async (url, options) => {
        calls.push({ url, body: JSON.parse(options.body), headers: options.headers });
        return { ok: true, status: 200 };
      },
    });
    assert.equal(result.status, 200);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://api.resend.com/emails");
    assert.equal(calls[0].headers.Authorization, "Bearer re_test");
    assert.equal(calls[0].body.from, DEFAULT_FROM);
    assert.deepEqual(calls[0].body.to, [TO]);
    assert.equal(calls[0].body.subject, "Patch request: ten-percent.co.uk");
    assert.equal(calls[0].body.reply_to, "test@example.com");
    assert.match(calls[0].body.text, /name: Test Lead/);
    assert.match(calls[0].body.text, /email: test@example.com/);
    assert.match(calls[0].body.text, /domain: ten-percent.co.uk/);
    assert.match(calls[0].body.text, /php: 8\.3\.35/);
    assert.match(calls[0].body.text, /verdict: vulnerable/);
    assert.match(calls[0].body.text, /host: SiteGround/);
    assert.match(calls[0].body.text, /message: Please quote/);
    assert.match(calls[0].body.text, /timestamp: 2026-10-24T23:41:40\+00:00/);
    assert.match(calls[0].body.text, /\{"domain":"ten-percent.co.uk","php":"8\.3\.35","verdict":"vulnerable","name":"Test Lead","email":"test@example.com","host":"SiteGround","message":"Please quote","ts":"2026-10-24T23:41:40\+00:00","ip":"127\.0\.0\.1","ua":"curl\/8\.9\.1"\}/);
  });

  it("returns 503 and does not call Resend when the API key is missing", async () => {
    let called = false;
    const result = await submitLead(base(), {
      env: {},
      fetchImpl: async () => {
        called = true;
        return { ok: true };
      },
    });
    assert.equal(result.status, 503);
    assert.match(result.body.error, /temporarily unavailable/);
    assert.equal(called, false);
  });

  it("rejects the honeypot, a bad email, and a bad CSRF token", async () => {
    const honeypot = await submitLead(base({ website: "http://spam.test" }), { env: { RESEND_API_KEY: "re_test" } });
    assert.equal(honeypot.status, 400);
    assert.equal(honeypot.body.error, "Submission rejected.");

    const email = await submitLead(base({ email: "not-an-email" }), { env: { RESEND_API_KEY: "re_test" } });
    assert.equal(email.status, 400);

    const csrf = await submitLead(base({ csrf: "nope" }), { env: { RESEND_API_KEY: "re_test" } });
    assert.equal(csrf.status, 400);
    assert.match(csrf.body.error, /session expired/i);
  });

  it("rate limits before sending", async () => {
    let called = false;
    const result = await submitLead(base(), {
      env: { RESEND_API_KEY: "re_test" },
      rateLimit: () => false,
      fetchImpl: async () => {
        called = true;
        return { ok: true };
      },
    });
    assert.equal(result.status, 429);
    assert.equal(called, false);
  });
});
