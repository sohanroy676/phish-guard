import { Link } from "react-router-dom";

export default function Privacy() {
  return (
    <section>
      <h1>Privacy</h1>
      <p>PhishGuard works offline. It never opens links or contacts any website.</p>
      <h2>What is kept</h2>
      <ul>
        <li>
          A keyed fingerprint (HMAC) of what you checked, which cannot be turned back into the link
          or email.
        </li>
        <li>The defanged host or sender domain, the result and the reasons shown.</li>
        <li>Never the full link, and never the text of an email.</li>
      </ul>
      <h2>How long</h2>
      <p>Checks are deleted automatically after 30 days.</p>
      <h2>Your control</h2>
      <p>
        Only you can see your history. You can erase it any time with Delete all on the{" "}
        <Link to="/history">History</Link> page.
      </p>
    </section>
  );
}
