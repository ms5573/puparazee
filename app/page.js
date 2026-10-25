import { Suspense } from "react";
import Checker from "./checker";
import ContactForm from "./contact-form";

export default function Page() {
  return (
    <>
      <a className="skip" href="#check">Skip to the checker</a>
      <header className="shell nav">
        <a className="logo" href="/">PHP<span>2</span>Shell</a>
        <nav className="nav-links" aria-label="Page">
          <a href="#check">Check</a>
          <a href="#scope">Scope</a>
          <a href="#issue">The issue</a>
          <a href="#contact">Quote</a>
        </nav>
      </header>
      <main className="shell">
        <section className="hero">
          <div>
            <p className="kicker">Free passive check</p>
            <h1>Is your site affected by PHP2Shell?</h1>
            <p className="lede">
              See the PHP version your server already advertises, and whether that version includes the October 2026 fix. The check is one normal request. Nothing is exploited.
            </p>
            <ul className="trust">
              <li>Headers only</li>
              <li>Public sites</li>
              <li>No account</li>
            </ul>
          </div>
          <Checker />
        </section>

        <section className="section" id="scope">
          <h2>What this check does</h2>
          <div className="split">
            <article className="card">
              <h3>What we check</h3>
              <ul>
                <li>One HEAD request, the same kind of request a browser makes for headers.</li>
                <li><code>Server</code> and <code>X-Powered-By</code>, looking for a PHP version banner.</li>
                <li>A short GET of <code>/wp-json/</code> to see if WordPress answers. The body is capped at 2KB.</li>
              </ul>
            </article>
            <article className="card">
              <h3>What we don’t</h3>
              <ul>
                <li>No exploit payloads, uploads, logins, or anything meant to trigger the bug.</li>
                <li>Not a confirmed test, and not a statement that a site has been compromised.</li>
                <li>Linux distributions often backport the fix and leave the version string unchanged, so a “vulnerable” banner can overstate exposure.</li>
              </ul>
            </article>
          </div>
        </section>

        <section className="section" id="issue">
          <h2>PHP2Shell, briefly</h2>
          <p>
            PHP2Shell is the name for two PHP vulnerabilities disclosed on 21 October 2026: CVE-2026-109618 and CVE-2026-109619. They can allow unauthenticated remote code execution on PHP that serves web requests. The PHP project shipped fixed releases the same day.
          </p>
          <div className="versions">
            <div className="version"><span>PHP 8.5</span><strong>8.5.12</strong></div>
            <div className="version"><span>PHP 8.4</span><strong>8.4.27</strong></div>
            <div className="version"><span>PHP 8.3</span><strong>8.3.36</strong></div>
            <div className="version"><span>PHP 8.2</span><strong>8.2.35</strong></div>
          </div>
          <p>
            PHP 8.1 and older are out of upstream support. Those branches do not get an official point release for this issue, so they need an upgrade to a supported branch, or a vendor that backports the fix.
          </p>
          <p className="sources">
            <a href="https://www.php.net/">php.net</a>
            <a href="https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w">GHSA-w8hw-w9fx-j79w</a>
            <a href="https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp">GHSA-6wmf-4rv5-p3rp</a>
          </p>
        </section>

        <Suspense fallback={<section className="section" id="contact"><h2>Get a quote</h2></section>}>
          <ContactForm />
        </Suspense>
      </main>
      <footer className="shell">
        <p>Marc Smith · <a href="mailto:marc.smith@mail.grokbot.com">marc.smith@mail.grokbot.com</a></p>
        <p>Checks are passive only: one HEAD request, and a short read of /wp-json/ when the site responds. No exploit traffic.</p>
      </footer>
    </>
  );
}
