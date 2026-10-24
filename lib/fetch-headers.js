"use strict";

const http = require("node:http");
const https = require("node:https");
const { isIP } = require("node:net");
const { CheckError } = require("./errors");

const USER_AGENT = "PuparazeeHeaderCheck/1.0 (+https://puparazee.com; passive PHP version header check)";

function bareHost(hostname) {
  const host = String(hostname || "");
  if (host.startsWith("[") && host.endsWith("]")) return host.slice(1, -1);
  return host;
}

function mapNetworkError(err) {
  if (err instanceof CheckError) return err;
  const code = err && err.code;
  if (code === "ETIMEDOUT" || code === "ECONNABORTED" || code === "UND_ERR_CONNECT_TIMEOUT") {
    return new CheckError("timeout");
  }
  if (
    typeof code === "string" &&
    (code.startsWith("CERT_") || code.startsWith("ERR_TLS_") || code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" || code === "DEPTH_ZERO_SELF_SIGNED_CERT")
  ) {
    return new CheckError("tls");
  }
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") return new CheckError("dns");
  return new CheckError("network");
}

// One GET, no request body. The response body is discarded as soon as headers arrive.
function requestHeaders(target, pin, timeoutMs) {
  if (!pin || typeof pin.address !== "string") return Promise.reject(new CheckError("network"));
  const budget = Number(timeoutMs);
  if (!Number.isFinite(budget) || budget <= 250) return Promise.reject(new CheckError("timeout"));

  const lib = target.protocol === "https:" ? https : http;
  const host = bareHost(target.hostname);
  const family = pin.family === 6 ? 6 : 4;
  const path = `${target.pathname || "/"}${target.search || ""}`;

  return new Promise((resolve, reject) => {
    let settled = false;
    let gotHeaders = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      fn(value);
    };

    const req = lib.request(
      {
        protocol: target.protocol,
        hostname: host,
        servername: isIP(host) ? undefined : host,
        port: target.port || (target.protocol === "https:" ? 443 : 80),
        path,
        method: "GET",
        autoSelectFamily: false,
        rejectUnauthorized: true,
        headers: {
          Host: target.host,
          "User-Agent": USER_AGENT,
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Encoding": "identity",
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
        res.on("error", () => {});
        const statusCode = res.statusCode || 0;
        const headers = res.headers;
        res.destroy();
        finish(resolve, { statusCode, headers });
      },
    );

    req.setTimeout(budget, () => {
      req.destroy();
      if (!gotHeaders) finish(reject, new CheckError("timeout"));
    });
    req.on("error", (err) => {
      if (!gotHeaders) finish(reject, mapNetworkError(err));
    });
    req.end();
  });
}

module.exports = { requestHeaders, USER_AGENT };
