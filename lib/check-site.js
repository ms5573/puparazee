"use strict";

const { normalizeInput } = require("./ssrf");
const { detectWordpress, buildVerdict } = require("./classify");
const { fetchHeaders, fetchSnippet } = require("./http-probe");

function invalidResult() {
  return {
    url: null,
    host: null,
    http_code: 0,
    server: "(none)",
    powered_by: null,
    php_version: null,
    php_class: null,
    wordpress: null,
    verdict: "invalid",
    message: "Not a valid public website URL. Enter a domain like example.com.",
  };
}

function unreachableResult(host, err) {
  return {
    url: null,
    host,
    http_code: 0,
    server: "(none)",
    powered_by: null,
    php_version: null,
    php_class: null,
    wordpress: null,
    verdict: "unreachable",
    message: `Could not reach ${host}: ${err || "connection failed"}`,
  };
}

async function checkSite(rawUrl, deps = {}) {
  const target = normalizeInput(rawUrl);
  if (!target) return invalidResult();

  const headersFn = deps.fetchHeaders || fetchHeaders;
  const snippetFn = deps.fetchSnippet || fetchSnippet;
  const head = await headersFn(target.href, deps);
  if (head && head.blocked) return invalidResult();
  if (!head || head.error || !head.httpCode) {
    return unreachableResult(target.hostname, head && head.error);
  }

  let body = "";
  try {
    const snippet = await snippetFn(`https://${target.hostname}/wp-json/`, deps);
    if (snippet && typeof snippet.body === "string") body = snippet.body.slice(0, 2048);
  } catch {
    body = "";
  }

  const wordpress = detectWordpress(head.headers, body);
  return buildVerdict({
    host: target.hostname,
    finalUrl: head.finalUrl || target.href,
    httpCode: head.httpCode,
    headers: head.headers,
    wordpress,
  });
}

module.exports = { checkSite };
