"use strict";

const { isIP, BlockList } = require("node:net");
const { lookup } = require("node:dns/promises");
const { CheckError } = require("./errors");

const blockList = new BlockList();

function add4(network, prefix) {
  blockList.addSubnet(network, prefix, "ipv4");
}

function add6(network, prefix) {
  blockList.addSubnet(network, prefix, "ipv6");
}

add4("0.0.0.0", 8);
add4("10.0.0.0", 8);
add4("100.64.0.0", 10);
add4("127.0.0.0", 8);
add4("169.254.0.0", 16);
add4("172.16.0.0", 12);
add4("192.0.0.0", 24);
add4("192.0.2.0", 24);
add4("192.168.0.0", 16);
add4("198.18.0.0", 15);
add4("198.51.100.0", 24);
add4("203.0.113.0", 24);
add4("224.0.0.0", 4);
add4("240.0.0.0", 4);
// Alibaba Cloud metadata address. It also falls inside CGNAT, pinned here by name.
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

const BLOCKED_SUFFIXES = [
  ".local",
  ".localhost",
  ".internal",
  ".localdomain",
  ".intranet",
  ".lan",
  ".home",
  ".corp",
  ".home.arpa",
  ".arpa",
];

const BLOCKED_NAMES = new Set([
  "localhost",
  "metadata",
  "metadata.google.internal",
  "metadata.google.com",
  "instance-data",
  "kubernetes",
  "kubernetes.default",
  "kubernetes.default.svc",
]);

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

function assertPublicHostname(hostname) {
  const host = bareHost(hostname);
  if (!host || host.length > 253) throw new CheckError("invalid_url");
  if (BLOCKED_NAMES.has(host) || BLOCKED_SUFFIXES.some((suffix) => host.endsWith(suffix))) {
    throw new CheckError("blocked");
  }
  if (isIP(host)) {
    if (isBlockedIp(host)) throw new CheckError("blocked");
    return host;
  }
  // Single-label names are how localhost and metadata hosts show up.
  if (!host.includes(".")) throw new CheckError("blocked");
  if (!/^[a-z0-9.-]+$/.test(host) || host.includes("..")) throw new CheckError("invalid_url");
  const labels = host.split(".");
  if (labels.some((label) => !label || label.startsWith("-") || label.endsWith("-"))) {
    throw new CheckError("invalid_url");
  }
  return host;
}

function canonicalizeUrl(url) {
  if (!(url instanceof URL)) throw new CheckError("invalid_url");
  if (url.username || url.password) throw new CheckError("invalid_url");
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new CheckError("invalid_url");
  const port = url.port;
  if (url.protocol === "https:" && port && port !== "443") throw new CheckError("blocked");
  if (url.protocol === "http:" && port && port !== "80") throw new CheckError("blocked");
  const host = assertPublicHostname(url.hostname);
  const clean = new URL(`${url.protocol}//${formatHost(host)}`);
  clean.pathname = url.pathname || "/";
  clean.search = url.search;
  if (clean.href.length > 2048) throw new CheckError("invalid_url");
  return clean;
}

function normalizePublicUrl(input) {
  if (typeof input !== "string") throw new CheckError("invalid_url");
  const trimmed = input.trim();
  if (!trimmed || trimmed.length > 2048) throw new CheckError("invalid_url");
  if (/[\u0000-\u001f\u007f\s\\]/.test(trimmed)) throw new CheckError("invalid_url");
  let withScheme = trimmed;
  if (!/^[a-z][a-z0-9+.-]*:/i.test(withScheme)) withScheme = `https://${withScheme}`;
  let url;
  try {
    url = new URL(withScheme);
  } catch {
    throw new CheckError("invalid_url");
  }
  return canonicalizeUrl(url);
}

async function resolvePublicAddress(hostname, lookupFn = lookup) {
  const host = assertPublicHostname(hostname);
  if (isIP(host)) return { address: host, family: isIP(host) };
  let records;
  try {
    records = await lookupFn(host, { all: true, verbatim: true });
  } catch {
    throw new CheckError("dns");
  }
  if (records && !Array.isArray(records) && records.address) records = [records];
  if (!Array.isArray(records) || records.length === 0) throw new CheckError("dns");
  for (const record of records) {
    if (!record || typeof record.address !== "string" || isBlockedIp(record.address)) {
      throw new CheckError("blocked");
    }
  }
  const chosen = records[0];
  return { address: chosen.address, family: chosen.family === 6 ? 6 : 4 };
}

module.exports = {
  bareHost,
  isBlockedIp,
  assertPublicHostname,
  canonicalizeUrl,
  normalizePublicUrl,
  resolvePublicAddress,
};
