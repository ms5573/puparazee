"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const page = fs.readFileSync(path.join(root, "app/page.js"), "utf8");
const checker = fs.readFileSync(path.join(root, "app/checker.js"), "utf8");
const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");

describe("landing copy", () => {
  it("names the issue, the fixed releases, and Marc", () => {
    const combined = `${page}\n${checker}\n${readme}`;
    for (const text of [
      "PHP2Shell",
      "CVE-2026-109618",
      "CVE-2026-109619",
      "8.5.12",
      "8.4.27",
      "8.3.36",
      "8.2.35",
      "8.1",
      "https://www.php.net/",
      "GHSA-w8hw-w9fx-j79w",
      "GHSA-6wmf-4rv5-p3rp",
      "Marc Smith",
      "marc.smith@mail.grokbot.com",
      "RESEND_API_KEY",
      "backport",
    ]) {
      assert.equal(combined.includes(text), true, text);
    }
  });

  it("does not keep the dog-voting site or ship exploit steps", () => {
    const files = ["app/page.js", "app/checker.js", "app/contact-form.js", "lib/check-site.js", "lib/http-probe.js", "lib/classify.js"];
    const combined = files.map((file) => fs.readFileSync(path.join(root, file), "utf8")).join("\n").toLowerCase();
    for (const text of ["chew matcher", "dog voting", "golden retriever", "php_value", "auto_detect_line_endings", "multipart/form-data"]) {
      assert.equal(combined.includes(text), false, text);
    }
  });
});
