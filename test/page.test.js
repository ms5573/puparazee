"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const html = fs.readFileSync(path.join(root, "index.html"), "utf8");
const script = fs.readFileSync(path.join(root, "script.js"), "utf8");
const css = fs.readFileSync(path.join(root, "style.css"), "utf8");

describe("landing page", () => {
  it("explains the fixed releases and points at the primary sources", () => {
    for (const text of [
      "PHP2Shell checker",
      "Is your site affected by PHP2Shell?",
      "CVE-2026-109618",
      "CVE-2026-109619",
      "8.5.12",
      "8.4.27",
      "8.3.36",
      "8.2.35",
      "8.1",
      "https://www.php.net/",
      "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
      "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
      "I'm Marc Smith. I follow PHP security issues and built this free checker.",
      "contact@puparazee.com",
      "can overstate exposure",
      "backport",
      "not a confirmed exploit test",
      "does not mean the site has been compromised",
      "Checks are passive only",
    ]) {
      assert.equal(html.includes(text), true, text);
    }
  });

  it("does not keep the dog-voting site or third-party analytics", () => {
    const combined = `${html}\n${script}\n${css}`.toLowerCase();
    for (const text of ["chew matcher", "dog voting", "golden retriever", "google-analytics", "googletagmanager", "plausible", "posthog", "segment.com", "innerhtml", "document.write"]) {
      assert.equal(combined.includes(text), false, text);
    }
  });
});
