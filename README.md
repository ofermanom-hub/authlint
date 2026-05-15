# 🔐 AuthLint

> A linter for enterprise auth configs. Paste your **SAML metadata**, a **JWT**, or an **OIDC discovery URL** — get a 15-year-implementation-veteran's review in 5 seconds.

**Live demo:** **https://authlint.onrender.com**
**Built by:** [Ofer Sadeh Man](https://www.linkedin.com/in/ofer-sadeh-man-60346582/)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/ofermanom-hub/authlint)

---

## Why this exists

After 15 years implementing enterprise SSO at DocuSign, Tipalti, and ClickSoftware/Salesforce, the same 12 misconfigurations turn week-1 go-lives into month-3 support tickets:

- SAML certs that quietly expired (and nobody noticed because rotation alarms weren't wired up)
- `alg: none` JWTs that some libraries cheerfully accept
- OIDC discovery docs still advertising the implicit flow in 2026
- IdPs that publish only HMAC `id_token_signing_alg_values_supported` — fine for confidential clients, broken for SPAs
- Single-key JWKS that make rotations a service-impacting event

AuthLint is the tool I wished customers had run *before* the kickoff meeting.

## What it catches

| Surface | Examples |
|---------|----------|
| **SAML metadata** | Cert expiry & key size, signing/digest algorithm strength, SSO/SLO endpoints & bindings, NameIDFormat, AuthnRequestsSigned / WantAssertionsSigned posture, AttributeStatement coverage |
| **JWT** | `alg: none`, HMAC for cross-org tokens, missing `iss`/`aud`/`exp`, oversized lifetime, missing `kid` (rotation hygiene) |
| **OIDC discovery** | Deprecated implicit/ROPC flows, missing PKCE, weak `id_token` algorithms, JWKS reachability + key rotation, HTTPS posture on every endpoint |

Each finding has a severity (`critical` → `ok`), a plain explanation, and a concrete fix. Tap **Explain →** to get a 2-sentence summary from Claude.

## Run locally

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
ANTHROPIC_API_KEY=sk-ant-... .venv/bin/python app.py
# → http://localhost:5050
```

## Deploy to Render

```bash
git init && git add . && git commit -m "init: authlint"
gh repo create authlint --public --source=. --push
# Render auto-detects render.yaml; add ANTHROPIC_API_KEY in the dashboard.
```

## API

```bash
curl -s https://authlint.onrender.com/api/scan \
  -H 'content-type: application/json' \
  -d '{"kind":"oidc","payload":"https://accounts.google.com"}' | jq
```

## Stack

- Python 3.11 + Flask
- `lxml` for SAML XML parsing
- `PyJWT` + `cryptography` for JWT / X.509
- htmx + Tailwind CDN (zero build step)
- Anthropic Claude Haiku for the per-finding explainer
- Render free tier (Python service)

## Roadmap

- [ ] "Compare two SAML metadata files" — staging-vs-prod drift detector (TAM flavour)
- [ ] Browser extension that lints the current site's `/.well-known/openid-configuration`
- [ ] Markdown export of the report for tickets/Confluence
- [ ] Configurable severity thresholds for CI gating

## License

MIT
