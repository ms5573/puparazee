"use strict";

const { isIP, BlockList } = require("node:net");
const { lookup } = require("node:dns/promises");

const blockList = new BlockList();

function add4(network, prefix) {
  blockList.addSubnet(network, prefix, "ipv4");
}

function add6(network, prefix) {
  blockList.addSubnet(network, prefix, "ipv6");
}

// PHP FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE, plus IPv6 equivalents.
add4("0.0.0.0", 8);
add4("10.0.0.0", 8);
add4("100.64.0.0", 10);
add4("127.0.0.0", 8);
add4("169.254.0.0", 16);
add4("172.16.0.0", 12);
add4("192.0.0.0", 24);
add4("192.0.2.0", 24);
add4("192.88.99.0", 24);
add4("192.168.0.0", 16);
add4("198.18.0.0", 15);
add4("198.51.100.0", 24);
add4("203.0.113.0", 24);
add4("224.0.0.0", 4);
add4("240.0.0.0", 4);
blockList.addAddress("100.100.100.200", "ipv4");

blockList.addAddress("::", "ipv6");
blockList.addAddress("::1", "ipv6");
add6("fc00::", 7);
add6("fe80::", 10);
add6("fec0::", 10);
add6("ff00::", 8);
add6("2001:db8::", 32);
add6("2001::", 32);
add6("2002::", 16);
add6("64:ff9b::", 96);
add6("64:ff9b:1::", 48);

const BLOCKED_SUFFIXES = [".local", ".localhost", ".internal", ".localdomain", ".intranet", ".lan", ".home", ".corp", ".arpa"];
const BLOCKED_NAMES = new Set([
  "localhost",
  "metadata",
  "metadata.google.internal",
  "metadata.google.com",
  "instance-data",
]);

class SsrfError extends Error {
  constructor(code) {
    super(code);
    this.name = "SsrfError";
    this.code = code;
  }
}

function bareHost(hostname) {
  let host = String(hostname || "").toLowerCase();
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  if (host.endsWith(".")) host = host.slice(0, -1);
  return host;
}

function isBlockedIp(ip) {
  const version = isIP(ip);
  if (version === 4) return blockList.check(ip, "ipv4");
  if (version === 6) return blockList.check(ip, "ipv6");
  return true;
}

function formatHost(host) {
  return isIP(host) === 6 ? `[${host}]` : host;
}

function assertHostname(hostname) {
  const host = bareHost(hostname);
  if (!host || host.length > 253) throw new SsrfError("invalid");
  if (BLOCKED_NAMES.has(host) || BLOCKED_SUFFIXES.some((suffix) => host.endsWith(suffix))) {
    throw new SsrfError("blocked");
  }
  if (isIP(host)) {
    if (isBlockedIp(host)) throw new SsrfError("blocked");
    return host;
  }
  if (!host.includes(".") || host.includes("..")) throw new SsrfError("invalid");
  if (!/^[a-z0-9.-]+$/.test(host)) throw new SsrfError("invalid");
  const labels = host.split(".");
  if (labels.some((label) => !label || label.length > 63 || label.startsWith("-") || label.endsWith("-"))) {
    throw new SsrfError("invalid");
  }
  return host;
}

function cleanUrl(url, { allowHttp = false, keepSearch = false } = {}) {
  if (!(url instanceof URL)) throw new SsrfError("invalid");
  if (url.username || url.password) throw new SsrfError("invalid");
  const httpsOk = url.protocol === "https:";
  const httpOk = allowHttp && url.protocol === "http:";
  if (!httpsOk && !httpOk) throw new SsrfError("invalid");
  const port = url.port;
  if (url.protocol === "https:" && port && port !== "443") throw new SsrfError("blocked");
  if (url.protocol === "http:" && port && port !== "80") throw new SsrfError("blocked");
  const host = assertHostname(url.hostname);
  const clean = new URL(`${url.protocol}//${formatHost(host)}`);
  clean.pathname = url.pathname || "/";
  if (keepSearch) clean.search = url.search;
  if (clean.href.length > 2048) throw new SsrfError("invalid");
  return clean;
}

// Match check.php: force https, keep the path, drop the query string.
function normalizeInput(input) {
  if (typeof input !== "string") return null;
  const trimmed = input.trim();
  if (!trimmed || trimmed.length > 2048) return null;
  if (/[\u0000-\u001f\u007f\s\\]/.test(trimmed)) return null;
  let withScheme = trimmed;
  if (!/^https?:\/\//i.test(withScheme)) withScheme = `https://${withScheme}`;
  let url;
  try {
    url = new URL(withScheme);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  url.protocol = "https:";
  url.port = "";
  try {
    return cleanUrl(url, { allowHttp: false });
  } catch {
    return null;
  }
}

async function resolveHost(hostname, lookupFn = lookup) {
  const host = assertHostname(hostname);
  if (isIP(host)) return { address: host, family: isIP(host) };
  let records;
  try {
    records = await lookupFn(host, { all: true, verbatim: true });
  } catch {
    throw new SsrfError("dns");
  }
  if (records && !Array.isArray(records) && records.address) records = [records];
  if (!Array.isArray(records) || records.length === 0) throw new SsrfError("dns");
  for (const record of records) {
    if (!record || typeof record.address !== "string" || isBlockedIp(record.address)) {
      throw new SsrfError("blocked");
    }
  }
  const chosen = records[0];
  return { address: chosen.address, family: chosen.family === 6 ? 6 : 4 };
}

module.exports = {
  SsrfError,
  bareHost,
  isBlockedIp,
  cleanUrl,
  normalizeInput,
  resolveHost,
};
