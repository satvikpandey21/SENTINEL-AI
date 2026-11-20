# Sentinel AI — Portfolio Screenshot & Demo Guide

This guide supports a professional, reproducible portfolio presentation. Capture only your **own controlled demo traffic** and avoid exposing administrator credentials, private URLs, personal identifiers, access tokens, cookies, HMAC secrets, or operational configuration.

## Recommended screenshot set

| File to save | Screen / evidence | What to show |
| --- | --- | --- |
| `01-security-overview.png` | **Security Overview** (`/`) | Overall security metrics, event activity, and a clean dashboard composition. |
| `02-security-events.png` | **Security Events** (`/events`) | Real recorded HTTP events, decisions, filtering, and clear 200/429 outcomes. |
| `03-threat-intelligence.png` | **Threat Intelligence** (`/threats`) | Explainable risk score, classification and evidence; use an expanded assessment if useful. |
| `04-client-investigation.png` | **Client Investigation** (`/clients`) | Pseudonymous client activity and investigation details without personal data. |
| `05-protection-policies.png` | **Protection Policies** (`/policies`) | Active rate-limit / enforcement policies and reviewable configuration. |
| `06-live-notifications.png` | **Notification Center** (bell in header) | Authenticated **Connected** stream and a meaningful live rate-limit/security alert. |
| `07-observability-grafana.png` | **Grafana** (local operator-only URL) | One of the provisioned operational dashboards with real data. |

**Best LinkedIn carousel:** 01 → 02 → 03 → 06 → 05. Add 07 for technical audiences. Optionally capture a terminal snippet showing controlled 200/429 responses, cropped to omit shell paths, usernames and secrets.

The admin console has seven sections: Security Overview, Security Events, Threat Intelligence, Client Investigation, Protection Policies, Audit Logs, and Settings. Audit Logs / Settings are useful for a full engineering demo, but less important than security detection and evidence in a LinkedIn carousel.

## Capture quality and privacy

1. Prefer a desktop browser at approximately **1440 × 900** or **1600 × 900**. Capture the app area without browser extensions, unrelated tabs, notifications, or address bar. Use the same resolution for a consistent carousel.
2. Generate fresh traffic **only against the private, owned demo API**. Give the worker time to process and check the UI shows genuine events and assessments. Do not simulate production statistics with fake visuals.
3. Show a normal, non-sensitive administrator account. Crop or redact usernames, client pseudonyms, timestamps and policy fields if they could disclose private activity. Never expose passwords, cookies, Authorization headers, token material, the .env files, secret files or the Cloudflare tunnel terminal.
4. Avoid screenshots of raw GitHub secrets/configuration or browser Network headers. Do not disclose live admin credentials or offer an open anonymous public demo of the administrative console.
5. Save the final approved images in `docs/assets/screenshots/` as PNG or well-optimized WebP, preferably **below 500 KB–1 MB each**, so the repository stays lightweight.
6. Once images exist, add a gallery of **actual relative Markdown images** to the top of `README.md`. Do **not** add broken screenshot placeholders.

## Short demo video (optional, 2–4 minutes)

Show the architecture diagram, sign in to a protected local/demo instance, generate controlled requests, observe 429 enforcement, show stored events, inspect one risk assessment, open a live notification, and finish with the GitHub Actions green workflow. Edit out credentials and setup interruptions.

## Accurate portfolio claims

- Say **"tested with a production-style HTTPS/WSS setup and demonstrated through a temporary public Cloudflare tunnel."**
- Do **not** say **"24/7 hosted," "permanently deployed," "production WAF,"** or **"ML blocks attacks automatically."** The experimental ML model supplies advisory evidence; deterministic policy enforcement is separate.
- GitHub README should prioritize **architecture, explainability, working features, test evidence, and reproducible setup** over a temporary tunnel URL.

## Local source of truth

See [architecture](architecture.md), [deployment guide](deployment-guide.md), [observability](observability.md), and [Phase 9 verification](day-9-verification.md) for technical detail and validation boundaries.
