"use strict";

const crypto = require("node:crypto");

const TO = "marc.smith@mail.grokbot.com";
const DEFAULT_FROM = "PHP2Shell Checker <onboarding@resend.dev>";
const VERDICTS = new Set(["patched", "vulnerable", "eol", "unknown", "unknown_wp", "unknown_version", "not_php", "unreachable", "invalid", ""]);

function clean(value, max) {
  return String(value ?? "")
    .replace(/<[^>]*>/g, "")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim()
    .slice(0, max);
}

function tokensMatch(a, b) {
  const left = Buffer.from(String(a || ""));
  const right = Buffer.from(String(b || ""));
  if (left.length === 0 || left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function timestamp(date) {
  return date.toISOString().replace(/\.\d{3}Z$/, "+00:00");
}

function leadRecord(fields, meta) {
  return {
    domain: fields.domain,
    php: fields.php,
    verdict: fields.verdict,
    name: fields.name,
    email: fields.email,
    host: fields.host,
    message: fields.message,
    ts: meta.ts,
    ip: meta.ip,
    ua: meta.ua,
  };
}

function formatLead(lead) {
  const lines = [
    "New patch request",
    "",
    `name: ${lead.name}`,
    `email: ${lead.email}`,
    `domain: ${lead.domain}`,
    `php: ${lead.php}`,
    `verdict: ${lead.verdict}`,
    `host: ${lead.host}`,
    `message: ${lead.message}`,
    `timestamp: ${lead.ts}`,
    `ip: ${lead.ip || ""}`,
    `ua: ${lead.ua || ""}`,
    "",
    JSON.stringify(lead),
  ];
  return lines.join("\n");
}

function validate(input) {
  const errors = [];
  if (!tokensMatch(input.csrf, input.cookie)) errors.push("Your session expired. Please submit again.");
  if (clean(input.website, 200) !== "") errors.push("Submission rejected.");
  const fields = {
    name: clean(input.name, 200),
    email: clean(input.email, 200),
    domain: clean(input.domain, 200),
    host: clean(input.host, 200),
    message: clean(input.message, 2000),
    php: clean(input.php, 40),
    verdict: clean(input.verdict, 40),
  };
  if (!fields.name) errors.push("Please enter your name.");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fields.email)) errors.push("Please enter a valid email address.");
  if (!fields.domain) errors.push("Please enter the site domain.");
  if (fields.verdict && !VERDICTS.has(fields.verdict)) fields.verdict = "";
  return { errors, fields };
}

async function submitLead(input, deps) {
  const { errors, fields } = validate(input);
  if (errors.length) return { status: 400, body: { error: errors[0], errors } };

  const now = deps.now ? deps.now() : Date.now();
  if (deps.rateLimit && !deps.rateLimit(input.ip || "unknown", now)) {
    return { status: 429, body: { error: "Too many requests. Please try again in an hour." } };
  }

  const apiKey = deps.env && deps.env.RESEND_API_KEY;
  if (!apiKey) {
    return {
      status: 503,
      body: { error: "Contact is temporarily unavailable. Email marc.smith@mail.grokbot.com directly." },
    };
  }

  const lead = leadRecord(fields, {
    ts: timestamp(deps.clock ? deps.clock() : new Date(now)),
    ip: input.ip || null,
    ua: clean(input.ua, 200),
  });
  const from = (deps.env && deps.env.RESEND_FROM) || DEFAULT_FROM;
  const fetchImpl = deps.fetchImpl || fetch;
  let response;
  try {
    response = await fetchImpl("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from,
        to: [TO],
        subject: `Patch request: ${lead.domain}`,
        reply_to: lead.email,
        text: formatLead(lead),
      }),
    });
  } catch {
    return {
      status: 502,
      body: { error: "Could not send your request. Please email marc.smith@mail.grokbot.com directly." },
    };
  }

  if (!response.ok) {
    return {
      status: 502,
      body: { error: "Could not send your request. Please email marc.smith@mail.grokbot.com directly." },
    };
  }

  return { status: 200, body: { ok: true, name: lead.name, domain: lead.domain, email: lead.email } };
}

module.exports = {
  TO,
  DEFAULT_FROM,
  clean,
  tokensMatch,
  leadRecord,
  formatLead,
  submitLead,
};
