"use strict";

const http = require("node:http");
const https = require("node:https");
const { isIP } = require("node:net");
const { SsrfError, cleanUrl, resolveHost } = require("./ssrf");

const UA = "PHP2Shell-Checker/1.0 (+passive; contact: marc.smith@mail.grokbot.com)";

function bareHost(hostname) {
  const host = String(hostname || "");
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

function mapError(err) {
  const code = err && (err.code || err.message);
  if (code === "ETIMEDOUT" || code === "ECONNABORTED" || code === "timeout" || code === "timed out") return "timed out";
  if (code === "ENOTFOUND" || code === "EAI_AGAIN" || code === "dns") return "Could not resolve host";
  if (
    typeof code === "string" &&
    (code.startsWith("CERT_") ||
      code.startsWith("ERR_TLS_") ||
      code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" ||
      code === "DEPTH_ZERO_SELF_SIGNED_CERT")
  ) {
    return "SSL connection error";
  }
  return "connection failed";
}

function headerMap(headers) {
  const out = {};
  for (const [name, value] of Object.entries(headers || {})) {
    if (Array.isArray(value)) out[name.toLowerCase()] = value.map((item) => String(item).trim());
    else if (value != null) out[name.toLowerCase()] = [String(value).trim()];
  }
  return out;
}

// One HEAD or a range-limited GET. No request body. DNS is pinned to the address already checked.
function requestOnce({ target, pin, method, timeoutMs, range, readBody }) {
  if (!pin || typeof pin.address !== "string") return Promise.resolve({ error: "connection failed" });
  const budget = Number(timeoutMs);
  if (!Number.isFinite(budget) || budget <= 200) return Promise.resolve({ error: "timed out" });

  const lib = target.protocol === "https:" ? https : http;
  const host = bareHost(target.hostname);
  const family = pin.family === 6 ? 6 : 4;

  return new Promise((resolve) => {
    let settled = false;
    let gotHeaders = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    const req = lib.request(
      {
        protocol: target.protocol,
        hostname: host,
        servername: isIP(host) ? undefined : host,
        port: target.port || (target.protocol === "https:" ? 443 : 80),
        path: `${target.pathname || "/"}${target.search || ""}`,
        method,
        autoSelectFamily: false,
        rejectUnauthorized: true,
        headers: {
          Host: target.host,
          "User-Agent": UA,
          Accept: "*/*",
          "Accept-Encoding": "identity",
          ...(range ? { Range: range } : {}),
        },
        lookup(_hostname, options, callback) {
          if (options && options.all) {
            callback(null, [{ address: pin.address, family }]);
            return;
          }
          callback(null, pin.address, family);
        },
      },
      (res) => {
        gotHeaders = true;
        const headers = headerMap(res.headers);
        const httpCode = res.statusCode || 0;
        if (!readBody) {
          res.on("error", () => {});
          res.destroy();
          finish({ httpCode, headers, finalUrl: target.href });
          return;
        }
        const chunks = [];
        let size = 0;
        const done = () => finish({ httpCode, headers, finalUrl: target.href, body: Buffer.concat(chunks).toString("utf8") });
        res.on("data", (chunk) => {
          if (size >= 2048) return;
          const slice = chunk.subarray(0, 2048 - size);
          chunks.push(slice);
          size += slice.length;
          if (size >= 2048) {
            res.destroy();
            done();
          }
        });
        res.on("end", done);
        res.on("error", done);
      },
    );

    req.setTimeout(budget, () => {
      req.destroy();
      if (!gotHeaders) finish({ error: "timed out", httpCode: 0 });
    });
    req.on("error", (err) => {
      if (!gotHeaders) finish({ error: mapError(err), httpCode: 0 });
    });
    req.end();
  });
}

async function follow(startUrl, options) {
  const resolve = options.resolve || resolveHost;
  const request = options.request || requestOnce;
  const maxRedirects = options.maxRedirects;
  const allowHttp = options.allowHttp !== false;
  let current;
  try {
    current = cleanUrl(new URL(startUrl), { allowHttp });
  } catch (err) {
    if (err instanceof SsrfError && err.code === "blocked") return { blocked: true, httpCode: 0 };
    return { error: "connection failed", httpCode: 0 };
  }

  const deadline = Date.now() + options.budgetMs;
  const seen = new Set();
  let redirects = 0;

  while (true) {
    if (seen.has(current.href)) return { error: "too many redirects", httpCode: 0 };
    seen.add(current.href);
    const remaining = deadline - Date.now();
    if (remaining <= 200) return { error: "timed out", httpCode: 0 };

    let pin;
    try {
      pin = await resolve(current.hostname);
    } catch (err) {
      if (err instanceof SsrfError && err.code === "blocked") {
        return redirects === 0 ? { blocked: true, httpCode: 0 } : { error: "redirect was not a public website", httpCode: 0 };
      }
      if (err instanceof SsrfError && err.code === "dns") return { error: "Could not resolve host", httpCode: 0 };
      return { error: "connection failed", httpCode: 0 };
    }

    const response = await request({
      target: current,
      pin,
      method: options.method,
      timeoutMs: remaining,
      range: options.range,
      readBody: Boolean(options.readBody),
    });
    if (!response || response.error || !response.httpCode) {
      return { error: (response && response.error) || "connection failed", httpCode: 0 };
    }

    const location = response.headers && response.headers.location && response.headers.location[0];
    const redirecting = [301, 302, 303, 307, 308].includes(response.httpCode) && location;
    if (!redirecting) return response;
    if (redirects >= maxRedirects) return { error: "too many redirects", httpCode: 0 };

    let next;
    try {
      next = cleanUrl(new URL(location, current), { allowHttp: true, keepSearch: true });
    } catch (err) {
      if (err instanceof SsrfError && err.code === "blocked") {
        return { error: "redirect was not a public website", httpCode: 0 };
      }
      return { error: "connection failed", httpCode: 0 };
    }
    current = next;
    redirects += 1;
  }
}

function fetchHeaders(url, deps = {}) {
  return follow(url, {
    method: "HEAD",
    maxRedirects: 4,
    budgetMs: 6000,
    allowHttp: false,
    readBody: false,
    resolve: deps.resolve,
    request: deps.request,
  });
}

function fetchSnippet(url, deps = {}) {
  return follow(url, {
    method: "GET",
    maxRedirects: 2,
    budgetMs: 6000,
    allowHttp: false,
    readBody: true,
    range: "bytes=0-2047",
    resolve: deps.resolve,
    request: deps.request,
  });
}

module.exports = {
  UA,
  requestOnce,
  fetchHeaders,
  fetchSnippet,
};
