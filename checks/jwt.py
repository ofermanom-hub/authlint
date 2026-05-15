"""JWT linter.

We do NOT verify signatures here (that requires the issuer's key). We
inspect the structural and policy properties that a senior implementer
flags on sight:

- alg: none, weak HMAC, RS256 vs ES256 trade-offs
- standard claim presence and sanity (iss, sub, aud, exp, iat, nbf)
- token lifetime
- kid presence (rotation hygiene)
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

import jwt as pyjwt

from .common import Finding, LintResult


WEAK_ALGS = {"none", "HS256", "HS384", "HS512"}
STRONG_ASYMMETRIC = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def lint_jwt(token: str) -> LintResult:
    result = LintResult(kind="jwt")
    token = token.strip()
    if not token:
        result.error = "Empty JWT input."
        return result

    parts = token.split(".")
    if len(parts) not in (2, 3):
        result.error = f"Not a JWT — expected 2 or 3 dot-separated segments, got {len(parts)}."
        return result

    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as e:
        result.error = f"Could not decode JWT segments: {e}"
        return result

    alg = header.get("alg", "")
    typ = header.get("typ", "")
    kid = header.get("kid")

    result.summary = {
        "alg": alg,
        "typ": typ or "(unset)",
        "kid": kid or "(unset)",
        "claims": sorted(payload.keys()),
    }

    # --- Algorithm --------------------------------------------------------
    if alg.lower() == "none":
        result.add(Finding(
            id="jwt.alg-none",
            title="alg: none — signature stripped",
            severity="critical",
            detail="A JWT with alg='none' is unsigned. Verifiers that accept 'none' (CVE-2015-9235 class) treat any payload as valid.",
            suggestion="Reject tokens with alg='none' at the verifier; only allow an explicit allow-list (e.g. ['RS256']).",
            evidence=f"header.alg = {alg!r}",
        ))
    elif alg in {"HS256", "HS384", "HS512"}:
        result.add(Finding(
            id="jwt.hmac-alg",
            title=f"HMAC signing ({alg})",
            severity="medium",
            detail="HMAC requires the verifier to hold the same secret as the signer — fine for internal service-to-service, risky when shared across boundaries or with public keys.",
            suggestion="If this token crosses an org/network boundary, switch to RS256/ES256 so verifiers hold only a public key.",
        ))
    elif alg in STRONG_ASYMMETRIC:
        result.add(Finding(
            id="jwt.alg-ok",
            title=f"Asymmetric signing ({alg})",
            severity="ok",
            detail="Verifiers only need the issuer's public key. Good baseline.",
        ))
    elif alg:
        result.add(Finding(
            id="jwt.alg-unknown",
            title=f"Unusual algorithm: {alg}",
            severity="medium",
            detail="Not in the common allow-list — verify the verifier library actually supports it.",
            suggestion="Standardise on RS256 or ES256 unless there's a specific reason.",
        ))

    # --- kid --------------------------------------------------------------
    if alg not in {"none", ""} and not kid and alg not in {"HS256", "HS384", "HS512"}:
        result.add(Finding(
            id="jwt.no-kid",
            title="No 'kid' header",
            severity="low",
            detail="Without a key-id, the verifier cannot tell which JWKS entry signed this token, complicating key rotation.",
            suggestion="Issue tokens with a 'kid' header and publish matching JWKS entries.",
        ))

    # --- Standard claims --------------------------------------------------
    now = datetime.now(timezone.utc).timestamp()
    for claim in ("iss", "sub", "aud", "exp", "iat"):
        if claim not in payload:
            sev = "high" if claim in {"iss", "exp", "aud"} else "medium"
            result.add(Finding(
                id=f"jwt.missing-{claim}",
                title=f"Missing standard claim: '{claim}'",
                severity=sev,
                detail={
                    "iss": "Without 'iss', the verifier cannot route to a JWKS or trust policy.",
                    "sub": "Without 'sub', the token has no subject identity.",
                    "aud": "Without 'aud', a token issued for service A can be replayed against service B.",
                    "exp": "Without 'exp', the token is effectively bearer-forever.",
                    "iat": "Without 'iat', token age (used for max-age policies and replay windows) cannot be assessed.",
                }[claim],
                suggestion=f"Include '{claim}' in the JWT claims set.",
            ))

    exp = payload.get("exp")
    iat = payload.get("iat")
    nbf = payload.get("nbf")

    if isinstance(exp, (int, float)):
        seconds_left = exp - now
        result.summary["seconds_to_expiry"] = int(seconds_left)
        if seconds_left < 0:
            result.add(Finding(
                id="jwt.expired",
                title=f"Token expired {int(-seconds_left)}s ago",
                severity="high",
                detail="The token is past its 'exp' timestamp.",
                suggestion="Refresh the token; verify clock skew tolerance on both sides (typically ±60s).",
            ))
        elif isinstance(iat, (int, float)):
            lifetime = exp - iat
            result.summary["lifetime_seconds"] = int(lifetime)
            if lifetime > 24 * 3600:
                result.add(Finding(
                    id="jwt.long-lifetime",
                    title=f"Long token lifetime ({int(lifetime / 3600)}h)",
                    severity="medium",
                    detail="Long-lived bearer tokens widen the blast radius of any leak.",
                    suggestion="Issue short-lived access tokens (5–60 min) paired with a refresh token or session.",
                ))

    if isinstance(nbf, (int, float)) and nbf > now + 300:
        result.add(Finding(
            id="jwt.future-nbf",
            title="'nbf' claim is in the future",
            severity="medium",
            detail="The token is not yet valid; verifiers will reject it until the nbf time.",
            suggestion="Check clock skew between issuer and verifier (NTP).",
        ))

    # Final compatibility check: use PyJWT to confirm decodable structure
    try:
        pyjwt.get_unverified_header(token)
    except pyjwt.PyJWTError as e:
        result.add(Finding(
            id="jwt.malformed",
            title="PyJWT could not parse the token header",
            severity="high",
            detail=str(e),
            suggestion="Re-issue the token; ensure standard JWS Compact serialization.",
        ))

    return result
