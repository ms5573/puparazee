"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";

const VERDICT_LABEL = {
  vulnerable: "Vulnerable",
  eol: "End-of-life PHP",
  unknown_wp: "WordPress, PHP version hidden",
};

const EMPTY = { domain: "", php: "", verdict: "", name: "", email: "", host: "", message: "", website: "" };

export default function ContactForm() {
  const params = useSearchParams();
  const [fields, setFields] = useState(EMPTY);
  const [csrf, setCsrf] = useState("");
  const [errors, setErrors] = useState([]);
  const [pending, setPending] = useState(false);
  const [sent, setSent] = useState(null);

  useEffect(() => {
    let ignore = false;
    fetch("/api/contact", { headers: { Accept: "application/json" } })
      .then((response) => response.json())
      .then((data) => {
        if (!ignore && data && data.csrf) setCsrf(data.csrf);
      })
      .catch(() => {});
    return () => {
      ignore = true;
    };
  }, []);

  useEffect(() => {
    const domain = params.get("domain") || "";
    const php = params.get("php") || "";
    const verdict = params.get("verdict") || "";
    if (domain || php || verdict) {
      setFields((current) => ({ ...current, domain, php, verdict }));
      setSent(null);
    }
  }, [params]);

  useEffect(() => {
    function onQuote(event) {
      const detail = event.detail || {};
      setFields((current) => ({
        ...current,
        domain: detail.domain || "",
        php: detail.php || "",
        verdict: detail.verdict || "",
      }));
      setSent(null);
      setErrors([]);
    }
    window.addEventListener("php2shell-quote", onQuote);
    return () => window.removeEventListener("php2shell-quote", onQuote);
  }, []);

  function update(name) {
    return (event) => setFields((current) => ({ ...current, [name]: event.target.value }));
  }

  async function onSubmit(event) {
    event.preventDefault();
    setPending(true);
    setErrors([]);
    try {
      const response = await fetch("/api/contact", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ ...fields, csrf }),
      });
      const data = await response.json();
      if (!response.ok) {
        setErrors(data.errors || [data.error || "Please submit the form again."]);
        return;
      }
      setSent(data);
    } catch {
      setErrors(["The form could not be reached. Email marc.smith@mail.grokbot.com directly."]);
    } finally {
      setPending(false);
    }
  }

  const summary = fields.domain && VERDICT_LABEL[fields.verdict]
    ? `${fields.domain} — ${VERDICT_LABEL[fields.verdict]}${fields.php ? `, PHP ${fields.php}` : ""}`
    : "";

  return (
    <section className="section" id="contact">
      <h2>Get a quote</h2>
      <p className="lede" style={{ marginTop: 0 }}>
        Optional. If you want someone to update PHP or move the site to a patched host, send a note. No access is needed until you approve a quote.
      </p>
      <div className="quote" style={{ padding: "1.15rem 1.2rem 1.3rem", marginTop: "1rem" }}>
        {sent ? (
          <div className="summary ok">
            <h3>Request received</h3>
            <p>
              Thanks, {sent.name}. We’ll look at {sent.domain} and reply to {sent.email} with a quote and next steps.
            </p>
          </div>
        ) : (
          <form onSubmit={onSubmit}>
            <input type="hidden" name="csrf" value={csrf} />
            <input type="hidden" name="php" value={fields.php} />
            <input type="hidden" name="verdict" value={fields.verdict} />
            <div className="hp" aria-hidden="true">
              <label>
                Website
                <input tabIndex={-1} autoComplete="off" name="website" value={fields.website} onChange={update("website")} />
              </label>
            </div>
            {summary ? (
              <div className="summary">
                <strong>From your check:</strong> {summary}
              </div>
            ) : null}
            {errors.length ? (
              <div className="summary err" role="alert">
                <ul>
                  {errors.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            <div className="fields">
              <label htmlFor="domain">Site domain</label>
              <input id="domain" name="domain" type="text" inputMode="url" value={fields.domain} onChange={update("domain")} required />

              <label htmlFor="name">Your name</label>
              <input id="name" name="name" type="text" autoComplete="name" value={fields.name} onChange={update("name")} required />

              <label htmlFor="email">Email</label>
              <input id="email" name="email" type="email" autoComplete="email" value={fields.email} onChange={update("email")} required />

              <label htmlFor="host">
                Hosting provider <span className="optional">(optional — GoDaddy, SiteGround, your own VPS)</span>
              </label>
              <input id="host" name="host" type="text" value={fields.host} onChange={update("host")} />

              <label htmlFor="message">
                Anything else? <span className="optional">(optional)</span>
              </label>
              <textarea id="message" name="message" value={fields.message} onChange={update("message")} />

              <button type="submit" disabled={pending || !csrf}>
                {pending ? "Sending…" : "Request a quote"}
              </button>
            </div>
            <p className="hint">These details are emailed to Marc so he can reply. They are not sold or added to a mailing list.</p>
          </form>
        )}
      </div>
    </section>
  );
}
