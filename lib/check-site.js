"use strict";

const { CheckError } = require("./errors");
const { canonicalizeUrl, normalizePublicUrl, resolvePublicAddress } = require("./ssrf");
const { classifyHeaders } = require("./classify");
const { requestHeaders } = require("./fetch-headers");

const MAX_REDIRECTS = 2;
const BUDGET_MS = 8000;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function headerLocation(headers) {
  if (!headers) return "";
  const value = headers.location ?? headers.Location;
  if (Array.isArray(value)) return String(value[0] || "");
  return value ? String(value) : "";
}

async function follow(startUrl, deps, deadline) {
  let current = canonicalizeUrl(startUrl);
  let redirects = 0;
  const seen = new Set();

  while (true) {
    if (seen.has(current.href)) throw new CheckError("redirect");
    seen.add(current.href);
    const remaining = deadline - Date.now();
    if (remaining <= 250) throw new CheckError("timeout");

    const pin = await deps.resolvePublicAddress(current.hostname);
    const response = await deps.requestHeaders(current, pin, Math.min(5000, remaining));
    const location = headerLocation(response.headers).trim();
    const redirecting = REDIRECT_STATUSES.has(response.statusCode) && location;

    if (redirecting && redirects >= MAX_REDIRECTS) throw new CheckError("redirect");
    if (redirecting) {
      let next;
      try {
        next = new URL(location, current);
      } catch {
        return pack(current, response);
      }
      if (next.href.length > 2048) throw new CheckError("redirect");
      current = canonicalizeUrl(next);
      redirects += 1;
      continue;
    }
    return pack(current, response);
  }
}

function pack(url, response) {
  const classified = classifyHeaders(response.headers);
  return {
    ...classified,
    finalUrl: url.href,
    httpStatus: response.statusCode || 0,
    schemeNote: null,
  };
}

async function checkSite(input, deps = {}) {
  const resolve = deps.resolvePublicAddress || resolvePublicAddress;
  const request = deps.requestHeaders || requestHeaders;
  const target = normalizePublicUrl(input);
  const deadline = Date.now() + BUDGET_MS;
  const used = { resolvePublicAddress: resolve, requestHeaders: request };

  if (target.protocol === "http:") {
    const httpsUrl = new URL(target.toString());
    httpsUrl.protocol = "https:";
    httpsUrl.port = "";
    try {
      return await follow(httpsUrl, used, deadline);
    } catch (err) {
      if (!(err instanceof CheckError) || !["timeout", "network", "tls"].includes(err.code)) throw err;
      if (Date.now() >= deadline) throw new CheckError("timeout");
      const result = await follow(target, used, deadline);
      result.schemeNote = "HTTPS did not connect, so this check used HTTP.";
      return result;
    }
  }

  return follow(target, used, deadline);
}

module.exports = { checkSite };
