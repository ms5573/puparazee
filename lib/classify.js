"use strict";

// First fixed release per supported branch. Same table as check.php.
const PHP_FIXED = {
  "8.5": "8.5.12",
  "8.4": "8.4.27",
  "8.3": "8.3.36",
  "8.2": "8.2.35",
};

const PHP_EOL_BRANCHES = new Set(["8.1", "8.0", "7.4", "7.3", "7.2", "7.1", "7.0", "5.6", "5.5", "5.4", "5.3", "5.2"]);

function classifyVersion(version) {
  const match = /^(\d+)\.(\d+)(?:\.(\d+))?(?:[-+].*)?$/.exec(String(version || ""));
  if (!match) return null;
  const branch = `${match[1]}.${match[2]}`;
  const full = `${match[1]}.${match[2]}.${match[3] || "0"}`;
  if (Object.prototype.hasOwnProperty.call(PHP_FIXED, branch)) {
    return compareVersions(full, PHP_FIXED[branch]) >= 0 ? "patched" : "vulnerable";
  }
  if (PHP_EOL_BRANCHES.has(branch)) return "eol";
  return null;
}

function compareVersions(left, right) {
  const a = left.split(".").map((part) => Number(part));
  const b = right.split(".").map((part) => Number(part));
  for (let i = 0; i < 3; i += 1) {
    const av = a[i] || 0;
    const bv = b[i] || 0;
    if (av > bv) return 1;
    if (av < bv) return -1;
  }
  return 0;
}

function headerList(headers, name) {
  if (!headers) return [];
  const value = headers[name] ?? headers[name.toLowerCase()];
  if (Array.isArray(value)) return value.map((item) => String(item));
  if (value == null || value === "") return [];
  return [String(value)];
}

function extractPhpVersion(server, poweredList) {
  const candidates = [server, ...poweredList];
  for (const candidate of candidates) {
    if (!candidate) continue;
    const match = /PHP\/([\d][\d.\-+a-z]*)/i.exec(candidate);
    if (match) return match[1];
  }
  return null;
}

function detectWordpress(headers, body) {
  const wp = { is_wp: false, evidence: null, wp_version: null };
  for (const value of headerList(headers, "x-powered-by")) {
    if (/wordpress/i.test(value) || /wp engine/i.test(value) || /plesk/i.test(value)) {
      wp.is_wp = true;
      wp.evidence = `X-Powered-By: ${value}`.slice(0, 300);
    }
  }
  if (body && (body.includes('"namespaces"') || body.includes("wp/v2"))) {
    wp.is_wp = true;
    wp.evidence = wp.evidence || "/wp-json/ REST API present";
  }
  return wp;
}

function buildVerdict({ host, finalUrl, httpCode, headers, wordpress }) {
  const server = headerList(headers, "server")[0] || "(none)";
  const poweredList = headerList(headers, "x-powered-by");
  const powered = poweredList[0] || null;
  const phpVersion = extractPhpVersion(server, poweredList);
  const serverLower = server.toLowerCase();
  const isPhp =
    phpVersion !== null ||
    serverLower.includes("litespeed") ||
    serverLower.includes("php-fpm") ||
    serverLower.includes("plesk");
  const wp = wordpress || { is_wp: false, evidence: null, wp_version: null };
  const result = {
    url: finalUrl || null,
    host: host || null,
    http_code: httpCode || 0,
    server,
    powered_by: powered,
    php_version: phpVersion,
    php_class: phpVersion ? classifyVersion(phpVersion) : null,
    wordpress: wp,
    verdict: null,
    message: "",
  };

  if (!isPhp && phpVersion === null && !wp.is_wp && !serverLower.includes("apache") && !serverLower.includes("nginx")) {
    result.verdict = "not_php";
    result.message = `Server reports ${server} and no PHP version — likely not a PHP site.`;
    return result;
  }

  if (phpVersion === null) {
    if (wp.is_wp) {
      result.verdict = "unknown_wp";
      result.message =
        "WordPress detected, but the server hides its PHP version. WordPress runs on PHP — ask your host which PHP build serves this site.";
    } else {
      result.verdict = "unknown";
      result.message = `Server type detected (${server}) but no PHP version disclosed. A deeper (ownership-verified) check can fingerprint it.`;
    }
    return result;
  }

  const wpLabel = wp.is_wp ? "this WordPress site" : "this site";
  const branch = /^(\d+\.\d+)/.exec(phpVersion);
  const fixed = branch ? PHP_FIXED[branch[1]] : null;
  switch (result.php_class) {
    case "patched":
      result.verdict = "patched";
      result.message = `PHP ${phpVersion} on ${wpLabel} — this version includes the PHP2Shell fix (Oct 2026). Confirm with your host that this is a backported/patched build, not just a matching version string.`;
      break;
    case "vulnerable":
      result.verdict = "vulnerable";
      result.message = `PHP ${phpVersion} on ${wpLabel} — vulnerable to PHP2Shell (CVE-2026-109618/109619). Update to ${fixed || "the latest patch"} or ask your host to apply the vendor backport.`;
      break;
    case "eol":
      result.verdict = "eol";
      result.message = `PHP ${phpVersion} on ${wpLabel} — this branch is end-of-life and gets NO official PHP2Shell fix. Most exposed category. Upgrade the branch, or use a vendor that backports (TuxCare, ZendPHP LTS, Remi, sury).`;
      break;
    default:
      result.verdict = "unknown_version";
      result.message = `PHP ${phpVersion} — unrecognized version format; classify manually.`;
  }
  return result;
}

module.exports = {
  PHP_FIXED,
  PHP_EOL_BRANCHES,
  classifyVersion,
  extractPhpVersion,
  detectWordpress,
  buildVerdict,
  headerList,
};
