"use strict";

const { checkSite } = require("../lib/check-site");
const { CheckError } = require("../lib/errors");
const { createRateLimiter } = require("../lib/rate-limit");

const allowIp = createRateLimiter({ limit: 8, windowMs: 60_000 });
const allowAll = createRateLimiter({ limit: 60, windowMs: 60_000 });

const DISCLAIMER =
  "Header version checks can overstate exposure. Linux distributions often backport fixes without changing the version string. This is not a confirmed exploit test.";

const MESSAGES = {
  invalid_url: "Enter a public website address, like https://example.com.",
  blocked: "That address is not checked. This tool only requests public websites on ports 80 and 443.",
  dns: "That host name did not resolve.",
  timeout: "The site did not respond in time.",
  network: "The site could not be reached.",
  tls: "HTTPS was not accepted for that host.",
  redirect: "The site redirected too many times for a passive check.",
};

function send(res, status, body) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(JSON.stringify(body));
}

function clientIp(req) {
  const real = req.headers && req.headers["x-real-ip"];
  if (typeof real === "string" && real.trim()) return real.trim().slice(0, 80);
  if (req.socket && req.socket.remoteAddress) return req.socket.remoteAddress;
  return "unknown";
}

async function readBody(req) {
  const declared = Number(req.headers && req.headers["content-length"]);
  if (Number.isFinite(declared) && declared > 8192) {
    const error = new CheckError("invalid_url");
    error.httpStatus = 413;
    throw error;
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 8192) {
      const error = new CheckError("invalid_url");
      error.httpStatus = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function handler(req, res) {
  if (!req || req.method !== "POST") {
    send(res, 405, { error: "method", message: "Send a POST request with a JSON url." });
    return;
  }

  const ip = clientIp(req);
  const now = Date.now();
  if (!allowAll.allow("all", now) || !allowIp.allow(ip, now)) {
    send(res, 429, { error: "rate_limited", message: "Too many checks from this network. Wait a minute and try again." });
    return;
  }

  try {
    const raw = await readBody(req);
    let payload;
    try {
      payload = JSON.parse(raw || "");
    } catch {
      send(res, 400, { error: "invalid_url", message: MESSAGES.invalid_url });
      return;
    }
    if (!payload || typeof payload.url !== "string") {
      send(res, 400, { error: "invalid_url", message: MESSAGES.invalid_url });
      return;
    }
    const result = await checkSite(payload.url);
    send(res, 200, { ...result, disclaimer: DISCLAIMER });
  } catch (err) {
    if (err instanceof CheckError) {
      const status = err.httpStatus || (err.code === "invalid_url" || err.code === "blocked" ? 400 : 502);
      send(res, status, { error: err.code, message: MESSAGES[err.code] || MESSAGES.network });
      return;
    }
    send(res, 500, { error: "network", message: MESSAGES.network });
  }
}

handler.resetRateLimitForTests = function resetRateLimitForTests() {
  allowIp.reset();
  allowAll.reset();
};

module.exports = handler;
