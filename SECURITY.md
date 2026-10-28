# Security Policy

## Supported versions

Deployment is continuous: every merge to `main` is published to
<https://threats.top>. Only the current `main` is supported. Older commits are
not patched; a revert is the rollback path.

## Report a vulnerability privately

Use GitHub's private vulnerability reporting on this repository:
**Security → Report a vulnerability**. That opens a private advisory visible
only to the maintainers.

Do not open a public issue, pull request, or discussion for a suspected
vulnerability. Do not include secrets, personal data, or live malware samples in
a report.

Please include:

- the affected URL, file, or workflow and the commit you tested;
- reproduction steps or a proof of concept;
- the impact you believe it has;
- any suggested fix or mitigation.

## What is in scope

- The static site at `threats.top`: XSS or HTML injection, unsafe URL handling,
  clickjacking, dependency-free script behaviour.
- The Pro API at `api.threats.top`: authentication or session bypass, CSRF,
  licence forgery or replay, admin route access control, order or customer
  enumeration, rate-limit bypass, CSV or STIX output injection, and CORS
  mistakes that expose credentials or data.
- Pro operational data in D1: exposure of names, emails, phone numbers,
  transaction references, or licence hashes; cross-customer access; audit-log
  tampering.
- Payment pages: order-form manipulation that changes the recorded amount,
  term, wallet, or method in a way the owner would not see at review.
- The data pipeline: validator bypasses, feed poisoning, provenance forgery,
  integrity checks that can be skipped.
- GitHub Actions and repository configuration: token or secret exposure,
  privilege escalation, workflow injection, supply-chain compromise.
- The published JSON contract at `/data/*.json`.

## Out of scope

- Vulnerabilities in upstream sources (NVD, CISA, GitHub, ransomware.live,
  OpenPhish, and others); report those to the source.
- Findings that require a compromised device, browser extension, or account.
- Reports produced only by an automated scanner with no demonstrated impact.
- Denial of service, spam, social engineering, and physical attacks.
- Recovering a transfer sent to the wrong chain, the wrong token contract, or a
  mistyped address; crypto transfers are irreversible by design.
- Disputes about a manual approval, a refusal, or a refund decision. Those go to
  the support address on the site, not the security channel.

## Secrets and test data

Never include a password, TOTP seed, session cookie, licence key, or real
customer record in a report. Use a throwaway order and a licence you created
yourself. The admin credentials are generated locally by the owner and are
never committed; if you find one in the repository or a build artefact, treat
that as a critical finding and report it privately without quoting the value.

## Response targets

- Acknowledgement: within 3 business days.
- Initial triage and severity assessment: within 5 business days.
- Fix or documented mitigation for confirmed issues: target 30 days for high
  severity, 90 days for others.

We will coordinate disclosure with you and credit you in the advisory unless you
ask to remain anonymous.

## No bounty

This project does not run a paid bug bounty program, and reporting a
vulnerability does not create an entitlement to a reward. Any future program will
be announced on the site.

## Safe harbour

Good-faith research that follows this policy is authorised. Stay within the scope
above, test only accounts and data you own, avoid privacy violations and service
disruption, and give us reasonable time to fix the issue before public
disclosure.
