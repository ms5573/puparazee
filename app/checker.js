"use client";

import { useState } from "react";

const LABELS = {
  patched: "Patched",
  vulnerable: "Vulnerable",
  eol: "End of life",
  unknown: "Unknown",
  unknown_wp: "WordPress, version hidden",
  unknown_version: "Unrecognized version",
  not_php: "Not PHP",
  unreachable: "Unreachable",
  invalid: "Invalid address",
  rate_limited: "Slow down",
};

const QUOTE = new Set(["vulnerable", "eol", "unknown_wp"]);

export default function Checker() {
  const [url, setUrl] = useState("");
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  async function onSubmit(event) {
    event.preventDefault();
    const value = url.trim();
    if (!value) {
      setResult(null);
      setError("Enter a domain like example.com.");
      return;
    }
    setPending(true);
    setError("");
    setResult(null);
    try {
      const response = await fetch("/api/check", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ url: value }),
      });
      const data = await response.json();
      if (data && data.verdict) setResult(data);
      else setError(data && data.message ? data.message : "The check could not be completed.");
    } catch {
      setError("The checker could not be reached. Try again in a moment.");
    } finally {
      setPending(false);
    }
  }

  function requestQuote(event) {
    event.preventDefault();
    const detail = {
      domain: result.host || "",
      php: result.php_version || "",
      verdict: result.verdict || "",
    };
    window.dispatchEvent(new CustomEvent("php2shell-quote", { detail }));
    const next = new URL(window.location.href);
    next.searchParams.set("domain", detail.domain);
    next.searchParams.set("php", detail.php);
    next.searchParams.set("verdict", detail.verdict);
    next.hash = "contact";
    window.history.replaceState(null, "", `${next.pathname}${next.search}${next.hash}`);
    document.getElementById("contact")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  return (
    <section className="panel" id="check" aria-label="Free URL check">
      <form onSubmit={onSubmit}>
        <label htmlFor="url">Website</label>
        <div className="row">
          <input
            id="url"
            name="url"
            type="text"
            inputMode="url"
            autoComplete="url"
            spellCheck="false"
            placeholder="yourdomain.com"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
          />
          <button type="submit" disabled={pending}>
            {pending ? "Checking…" : "Check my site"}
          </button>
        </div>
      </form>
      <p className="hint">One HEAD request, then a short read of /wp-json/ if the site answers. Nothing else is sent.</p>
      <div className="result-slot" aria-live="polite">
        {error ? (
          <div className="result result-unreachable">
            <h3>Check not completed</h3>
            <p>{error}</p>
          </div>
        ) : null}
        {result ? (
          <div className={`result result-${result.verdict || "unknown"}`}>
            <h3>{LABELS[result.verdict] || "Result"}</h3>
            <p>{result.message}</p>
            {result.verdict !== "invalid" && result.verdict !== "rate_limited" ? (
              <dl className="meta">
                <div>
                  <dt>Host</dt>
                  <dd>{result.host || "—"}</dd>
                </div>
                <div>
                  <dt>Server</dt>
                  <dd>{result.server || "(none)"}</dd>
                </div>
                <div>
                  <dt>X-Powered-By</dt>
                  <dd>{result.powered_by || "(none)"}</dd>
                </div>
                <div>
                  <dt>PHP version</dt>
                  <dd>{result.php_version || "(not disclosed)"}</dd>
                </div>
                <div>
                  <dt>WordPress</dt>
                  <dd>{result.wordpress && result.wordpress.is_wp ? `yes — ${result.wordpress.evidence || ""}` : "not detected"}</dd>
                </div>
              </dl>
            ) : null}
            <p className="fine">
              Header versions can overstate exposure when a distributor backports a fix without changing the version string. This is not an exploit test.
            </p>
            {QUOTE.has(result.verdict) ? (
              <div className="cta">
                <p>If you want a hand updating this site, you can request a quote. The check stays free, and you don’t grant access until you approve one.</p>
                <a className="button" href={`/?domain=${encodeURIComponent(result.host || "")}&php=${encodeURIComponent(result.php_version || "")}&verdict=${encodeURIComponent(result.verdict)}#contact`} onClick={requestQuote}>
                  Request a quote
                </a>
              </div>
            ) : null}
          </div>
        ) : null}
      </div>
    </section>
  );
}
