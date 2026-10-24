"use strict";

// Upstream releases that contain the October 21, 2026 fixes.
const FIXED = {
  8: { 2: 35, 3: 36, 4: 27, 5: 12 },
};

const NON_PHP = [
  /\bexpress\b/i,
  /\basp\.net\b/i,
  /\bnext\.js\b/i,
  /\bservlet\b/i,
  /\btomcat\b/i,
  /\bjetty\b/i,
  /\bkestrel\b/i,
  /\bgunicorn\b/i,
  /\buvicorn\b/i,
  /\bwerkzeug\b/i,
  /\bcowboy\b/i,
  /\bnode\.js\b/i,
  /\bphusion passenger\b/i,
  /\bwsgi\b/i,
];

function readHeader(headers, name) {
  if (!headers) return "";
  const value = headers[name.toLowerCase()] ?? headers[name];
  if (Array.isArray(value)) return value.join(", ");
  if (value == null) return "";
  return String(value);
}

function cleanHeader(value) {
  const cleaned = String(value).replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim();
  if (!cleaned) return null;
  return cleaned.slice(0, 180);
}

function parsePhpVersion(headers) {
  const sources = [readHeader(headers, "x-powered-by"), readHeader(headers, "server")];
  for (const source of sources) {
    const match = /PHP\/(\d+)\.(\d+)\.(\d+)([A-Za-z0-9._-]*)/i.exec(source);
    if (!match) continue;
    const suffix = match[4] || "";
    return {
      major: Number(match[1]),
      minor: Number(match[2]),
      patch: Number(match[3]),
      raw: `${match[1]}.${match[2]}.${match[3]}`,
      suffix,
      stable: !/alpha|beta|rc|dev/i.test(suffix),
    };
  }
  return null;
}

function looksLikeWordPress(headers) {
  const link = readHeader(headers, "link");
  const pingback = readHeader(headers, "x-pingback");
  const redirectBy = readHeader(headers, "x-redirect-by");
  return /api\.w\.org/i.test(link) || /xmlrpc\.php/i.test(pingback) || /wordpress/i.test(redirectBy);
}

function formatVersion(php) {
  if (!php) return null;
  if (!php.suffix || php.stable) return php.raw;
  return `${php.raw}${php.suffix}`.slice(0, 40);
}

function decide(php, wordpress, banner) {
  if (php && !php.stable) {
    return {
      status: "unknown",
      summary: `Headers report a pre-release PHP version (${formatVersion(php)}). This checker only compares stable releases with the published fixes.`,
    };
  }
  if (php) {
    const { major, minor, patch, raw } = php;
    if (major < 8 || (major === 8 && minor <= 1)) {
      return {
        status: "eol",
        summary: `Headers report PHP ${raw}. PHP 8.1 and older are out of upstream support for this issue, so they need an upgrade to a fixed release on PHP 8.2 or newer. A vendor backport would not show up in this version string.`,
      };
    }
    const fixedPatch = FIXED[major] && FIXED[major][minor];
    if (fixedPatch == null) {
      return {
        status: "unknown",
        summary: `Headers report PHP ${raw}. This checker knows the fixed lines for PHP 8.2, 8.3, 8.4, and 8.5 only.`,
      };
    }
    const fixed = `${major}.${minor}.${fixedPatch}`;
    if (patch >= fixedPatch) {
      return {
        status: "likely_patched",
        summary: `Headers report PHP ${raw}. The fixed release for the ${major}.${minor} branch is ${fixed}. The advertised version is that release or newer. This is not proof the running build contains the patch.`,
      };
    }
    return {
      status: "likely_affected",
      summary: `Headers report PHP ${raw}. The fixed release for the ${major}.${minor} branch is ${fixed}. The advertised version is older. Distributions often backport the fix without changing this string, so this can overstate exposure. It does not mean the site has been compromised.`,
    };
  }
  if (wordpress) {
    return {
      status: "unknown",
      summary:
        "Response headers look like WordPress, which runs on PHP, but they do not include a PHP version. Many hosts hide that version. Check the PHP build on the server or with the host.",
    };
  }
  if (NON_PHP.some((pattern) => pattern.test(banner)) && !/\bphp\b/i.test(banner)) {
    return {
      status: "not_php",
      summary:
        "Response headers name a non-PHP stack and do not mention PHP. A proxy can still hide a PHP origin. This is not proof the site is free of PHP.",
    };
  }
  return {
    status: "unknown",
    summary:
      "Response headers do not include a PHP version. That is common, because many servers hide X-Powered-By. This check cannot tell whether PHP is installed.",
  };
}

function classifyHeaders(headers) {
  const php = parsePhpVersion(headers);
  const wordpress = looksLikeWordPress(headers);
  const xPoweredBy = cleanHeader(readHeader(headers, "x-powered-by"));
  const server = cleanHeader(readHeader(headers, "server"));
  const banner = `${xPoweredBy || ""} ${server || ""}`;
  const decision = decide(php, wordpress, banner);
  return {
    status: decision.status,
    summary: decision.summary,
    phpVersion: formatVersion(php),
    wordpress,
    xPoweredBy,
    server,
  };
}

module.exports = {
  FIXED,
  classifyHeaders,
  parsePhpVersion,
  looksLikeWordPress,
};
