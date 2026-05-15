"""OIDC discovery linter.

Fetches /.well-known/openid-configuration and surfaces:

- deprecated flows (implicit, ROPC)
- PKCE support
- JWKS reachability + key count
- signing alg quality
- missing endpoints (userinfo, end_session_endpoint)
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

import requests

from .common import Finding, LintResult


DEFAULT_TIMEOUT = 8

DEPRECATED_RESPONSE_TYPES = {
    "token": "Implicit flow (returns access_token in URL fragment — deprecated by OAuth 2.1).",
    "id_token token": "Implicit flow variant — deprecated.",
    "token id_token": "Implicit flow variant — deprecated.",
}

DEPRECATED_GRANT_TYPES = {
    "password": "Resource Owner Password Credentials grant — collects user credentials in the client, deprecated by OAuth 2.1.",
    "implicit": "Implicit grant — deprecated.",
}

WEAK_ID_TOKEN_ALGS = {"HS256", "HS384", "HS512", "none"}


def _normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if not raw.lower().startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc:
        return ""
    if not parsed.path or parsed.path == "/":
        return raw.rstrip("/") + "/.well-known/openid-configuration"
    return raw


def lint_oidc(url: str) -> LintResult:
    result = LintResult(kind="oidc")
    url = _normalize_url(url)
    if not url:
        result.error = "Empty or unparseable URL."
        return result

    if not url.lower().startswith("https://"):
        result.add(Finding(
            id="oidc.discovery-not-https",
            title="Discovery URL is not HTTPS",
            severity="high",
            detail="OIDC discovery documents are how clients learn JWKS and endpoints — fetching over HTTP allows MITM substitution of those values.",
            suggestion="Always publish and consume the discovery document over HTTPS.",
            evidence=url,
        ))

    try:
        resp = requests.get(url, timeout=DEFAULT_TIMEOUT, headers={"Accept": "application/json"})
    except requests.RequestException as e:
        result.error = f"Could not fetch {url}: {e}"
        return result

    if resp.status_code != 200:
        result.error = f"Discovery endpoint returned HTTP {resp.status_code}."
        return result

    try:
        doc = resp.json()
    except ValueError:
        result.error = "Discovery endpoint did not return valid JSON."
        return result

    result.summary = {
        "issuer": doc.get("issuer"),
        "discovery_url": url,
        "endpoints": {
            k: doc.get(k)
            for k in (
                "authorization_endpoint",
                "token_endpoint",
                "userinfo_endpoint",
                "jwks_uri",
                "end_session_endpoint",
                "introspection_endpoint",
                "revocation_endpoint",
            )
            if doc.get(k)
        },
    }

    # --- Endpoint sanity --------------------------------------------------
    required = ["authorization_endpoint", "token_endpoint", "jwks_uri"]
    missing = [r for r in required if not doc.get(r)]
    if missing:
        result.add(Finding(
            id="oidc.missing-endpoints",
            title=f"Missing required endpoint(s): {', '.join(missing)}",
            severity="critical",
            detail="An OIDC client cannot complete a code flow without these.",
            suggestion="Verify the discovery document is the canonical one for this issuer.",
        ))
    if not doc.get("userinfo_endpoint"):
        result.add(Finding(
            id="oidc.no-userinfo",
            title="No userinfo_endpoint advertised",
            severity="low",
            detail="Clients that need claims beyond the id_token will be unable to fetch them.",
            suggestion="Expose /userinfo if the provider supports it.",
        ))
    if not doc.get("end_session_endpoint"):
        result.add(Finding(
            id="oidc.no-end-session",
            title="No end_session_endpoint (RP-Initiated Logout)",
            severity="low",
            detail="Federated logout is increasingly required by SOC 2 / ISO 27001 controls.",
            suggestion="Implement OIDC RP-Initiated Logout if the platform supports it.",
        ))

    for key in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri", "end_session_endpoint"):
        val = doc.get(key)
        if val and not val.lower().startswith("https://"):
            result.add(Finding(
                id=f"oidc.{key.replace('_', '-')}-not-https",
                title=f"{key} is not HTTPS",
                severity="high",
                detail="OIDC endpoints carry tokens or credentials; all must be HTTPS.",
                suggestion="Move this endpoint behind HTTPS.",
                evidence=val,
            ))

    # --- Deprecated flows -------------------------------------------------
    response_types = doc.get("response_types_supported", []) or []
    grant_types = doc.get("grant_types_supported", []) or []
    result.summary["response_types"] = response_types
    result.summary["grant_types"] = grant_types

    for rt in response_types:
        key = " ".join(sorted(rt.split()))
        for dep_key, msg in DEPRECATED_RESPONSE_TYPES.items():
            if sorted(dep_key.split()) == key.split():
                result.add(Finding(
                    id=f"oidc.deprecated-response-{re.sub(r'[^a-z]+', '-', dep_key)}",
                    title=f"Deprecated response_type advertised: {rt!r}",
                    severity="medium",
                    detail=msg,
                    suggestion="Drop implicit flows; require Authorization Code with PKCE.",
                ))

    for gt in grant_types:
        if gt in DEPRECATED_GRANT_TYPES:
            result.add(Finding(
                id=f"oidc.deprecated-grant-{gt}",
                title=f"Deprecated grant_type advertised: {gt!r}",
                severity="high" if gt == "password" else "medium",
                detail=DEPRECATED_GRANT_TYPES[gt],
                suggestion="Remove from grant_types_supported; migrate clients to Authorization Code + PKCE.",
            ))

    # --- PKCE -------------------------------------------------------------
    pkce = doc.get("code_challenge_methods_supported") or []
    result.summary["pkce_methods"] = pkce
    if not pkce:
        result.add(Finding(
            id="oidc.no-pkce",
            title="PKCE not advertised",
            severity="high",
            detail="code_challenge_methods_supported is missing — public clients have no protection against authorization-code interception.",
            suggestion="Advertise 'S256' (and require it for public clients).",
        ))
    elif "plain" in pkce and "S256" not in pkce:
        result.add(Finding(
            id="oidc.pkce-plain-only",
            title="PKCE only supports 'plain'",
            severity="high",
            detail="'plain' offers no cryptographic protection over the code verifier.",
            suggestion="Add S256 and prefer it over 'plain'.",
        ))

    # --- id_token signing alg --------------------------------------------
    id_token_algs = doc.get("id_token_signing_alg_values_supported", []) or []
    result.summary["id_token_algs"] = id_token_algs
    if "none" in id_token_algs:
        result.add(Finding(
            id="oidc.id-token-alg-none",
            title="id_token_signing_alg_values_supported includes 'none'",
            severity="critical",
            detail="A client mis-configured to accept 'none' will trust unsigned id_tokens.",
            suggestion="Remove 'none' from id_token_signing_alg_values_supported.",
        ))
    if id_token_algs and set(id_token_algs) <= WEAK_ID_TOKEN_ALGS:
        result.add(Finding(
            id="oidc.id-token-hmac-only",
            title="id_token signing is HMAC-only",
            severity="medium",
            detail="Clients must hold the shared secret to verify — fine for confidential clients but breaks public/SPA use.",
            suggestion="Also support RS256 or ES256.",
        ))

    # --- JWKS reachability ------------------------------------------------
    jwks_uri = doc.get("jwks_uri")
    if jwks_uri:
        try:
            jwks_resp = requests.get(jwks_uri, timeout=DEFAULT_TIMEOUT, headers={"Accept": "application/json"})
            if jwks_resp.status_code != 200:
                result.add(Finding(
                    id="oidc.jwks-unreachable",
                    title=f"jwks_uri returned HTTP {jwks_resp.status_code}",
                    severity="high",
                    detail="Clients cannot verify id_tokens if JWKS is not fetchable.",
                    suggestion="Verify the jwks_uri is publicly resolvable and serves cache-friendly JSON.",
                    evidence=jwks_uri,
                ))
            else:
                try:
                    keys = jwks_resp.json().get("keys", [])
                    result.summary["jwks_key_count"] = len(keys)
                    if not keys:
                        result.add(Finding(
                            id="oidc.jwks-empty",
                            title="JWKS contains zero keys",
                            severity="critical",
                            detail="No signing material is published — id_token verification is impossible.",
                            suggestion="Publish active signing keys and a 'kid' for each.",
                        ))
                    elif len(keys) == 1:
                        result.add(Finding(
                            id="oidc.jwks-single-key",
                            title="JWKS publishes only a single key",
                            severity="low",
                            detail="Healthy rotation overlaps two keys — old (verify-only) and new (signing).",
                            suggestion="During rotation windows, publish both keys with distinct 'kid' values.",
                        ))
                except ValueError:
                    result.add(Finding(
                        id="oidc.jwks-invalid-json",
                        title="JWKS endpoint did not return JSON",
                        severity="high",
                        detail="Clients will fail to parse the key set.",
                        suggestion="Serve the JWKS with Content-Type: application/json.",
                    ))
        except requests.RequestException as e:
            result.add(Finding(
                id="oidc.jwks-fetch-error",
                title=f"Could not fetch jwks_uri",
                severity="high",
                detail=str(e),
                suggestion="Confirm DNS, TLS, and firewall reachability of the JWKS endpoint.",
            ))

    # --- Scopes -----------------------------------------------------------
    scopes = doc.get("scopes_supported", []) or []
    result.summary["scopes"] = scopes
    if scopes and "openid" not in scopes:
        result.add(Finding(
            id="oidc.no-openid-scope",
            title="'openid' scope not in scopes_supported",
            severity="medium",
            detail="A discovery doc that omits the 'openid' scope is borderline non-conformant.",
            suggestion="Advertise 'openid' explicitly.",
        ))

    return result
