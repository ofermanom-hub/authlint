"""SAML metadata comparator — staging vs production drift detector.

Use case: customer reports "staging works, prod doesn't". This module
extracts the comparison-relevant facts from two metadata files and
returns a structured, severity-ranked diff. This is the artefact a
TAM/Implementation Manager produces in week 1 of triage.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional

from lxml import etree

NS = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "alg": "urn:oasis:names:tc:SAML:metadata:algsupport",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}

# Field-level severity for diff classification. Tuned by what a senior
# implementer would actually escalate on.
FIELD_SEVERITY = {
    "entityID": "critical",
    "role": "critical",
    "cert_fingerprints": "high",
    "endpoints.SingleSignOnService": "high",
    "endpoints.AssertionConsumerService": "high",
    "endpoints.SingleLogoutService": "medium",
    "nameid_formats": "high",
    "signing_algorithms": "medium",
    "digest_algorithms": "medium",
    "AuthnRequestsSigned": "high",
    "WantAssertionsSigned": "high",
    "WantAuthnRequestsSigned": "medium",
    "attributes": "medium",
    "cert_expiries": "info",
    "cert_key_bits": "high",
}


@dataclass
class DiffItem:
    field: str
    severity: str
    left: Any
    right: Any
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CompareResult:
    left_summary: dict = field(default_factory=dict)
    right_summary: dict = field(default_factory=dict)
    diffs: list = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "left_summary": self.left_summary,
            "right_summary": self.right_summary,
            "diffs": [d.to_dict() for d in self.diffs],
            "error": self.error,
        }


def _fingerprint(cert_b64: str) -> str:
    try:
        der = base64.b64decode("".join(cert_b64.split()))
        return hashlib.sha256(der).hexdigest()[:16]  # short fingerprint for display
    except Exception:
        return "<unparseable>"


def _cert_info(cert_b64: str) -> dict:
    info = {"fingerprint": _fingerprint(cert_b64)}
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        der = base64.b64decode("".join(cert_b64.split()))
        cert = x509.load_der_x509_certificate(der)
        info["not_after"] = cert.not_valid_after_utc.isoformat()
        info["not_before"] = cert.not_valid_before_utc.isoformat()
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            info["key_bits"] = key.key_size
        elif isinstance(key, ec.EllipticCurvePublicKey):
            info["key_bits"] = key.curve.key_size
    except Exception:
        pass
    return info


def parse_facts(xml_text: str) -> dict:
    """Extract comparison-relevant facts from a SAML EntityDescriptor."""
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    root = etree.fromstring(xml_text.strip().encode("utf-8"), parser=parser)

    if root.tag == f"{{{NS['md']}}}EntitiesDescriptor":
        entity = root.find("md:EntityDescriptor", NS)
        if entity is None:
            raise ValueError("EntitiesDescriptor contained no EntityDescriptor.")
    elif root.tag == f"{{{NS['md']}}}EntityDescriptor":
        entity = root
    else:
        raise ValueError(f"Not SAML metadata (root: {root.tag})")

    idp = entity.find("md:IDPSSODescriptor", NS)
    sp = entity.find("md:SPSSODescriptor", NS)
    role_el = idp if idp is not None else sp
    role = "IdP" if idp is not None else ("SP" if sp is not None else "unknown")

    facts: dict = {
        "entityID": entity.get("entityID", ""),
        "role": role,
        "certs": [],
        "endpoints": {
            "SingleSignOnService": [],
            "SingleLogoutService": [],
            "AssertionConsumerService": [],
        },
        "nameid_formats": [],
        "signing_algorithms": [],
        "digest_algorithms": [],
        "AuthnRequestsSigned": None,
        "WantAssertionsSigned": None,
        "WantAuthnRequestsSigned": None,
        "attributes": [],
    }

    if role_el is None:
        return facts

    for cert_el in role_el.findall("md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate", NS):
        if cert_el.text:
            facts["certs"].append(_cert_info(cert_el.text))

    for tag in ("SingleSignOnService", "SingleLogoutService", "AssertionConsumerService"):
        for el in role_el.findall(f"md:{tag}", NS):
            facts["endpoints"][tag].append({
                "binding": (el.get("Binding") or "").rsplit(":", 1)[-1],
                "location": el.get("Location") or "",
            })

    facts["nameid_formats"] = sorted({el.text for el in role_el.findall("md:NameIDFormat", NS) if el.text})

    for el in entity.findall(".//alg:SigningMethod", NS):
        a = el.get("Algorithm")
        if a:
            facts["signing_algorithms"].append(a)
    facts["signing_algorithms"] = sorted(set(facts["signing_algorithms"]))

    for el in entity.findall(".//alg:DigestMethod", NS):
        a = el.get("Algorithm")
        if a:
            facts["digest_algorithms"].append(a)
    facts["digest_algorithms"] = sorted(set(facts["digest_algorithms"]))

    if role == "SP":
        facts["AuthnRequestsSigned"] = role_el.get("AuthnRequestsSigned", "false").lower() == "true"
        facts["WantAssertionsSigned"] = role_el.get("WantAssertionsSigned", "false").lower() == "true"
    elif role == "IdP":
        facts["WantAuthnRequestsSigned"] = role_el.get("WantAuthnRequestsSigned", "false").lower() == "true"

    facts["attributes"] = sorted({el.get("Name") for el in role_el.findall("saml:Attribute", NS) if el.get("Name")})

    return facts


def _summary(facts: dict) -> dict:
    return {
        "entityID": facts.get("entityID", ""),
        "role": facts.get("role", ""),
        "cert_count": len(facts.get("certs", [])),
        "sso_endpoints": len(facts.get("endpoints", {}).get("SingleSignOnService", [])),
        "acs_endpoints": len(facts.get("endpoints", {}).get("AssertionConsumerService", [])),
        "nameid_formats": facts.get("nameid_formats", []),
    }


def _endpoint_set(eps: list[dict]) -> set[tuple[str, str]]:
    return {(e.get("binding", ""), e.get("location", "")) for e in eps}


def diff_saml(left_xml: str, right_xml: str, left_label: str = "Staging", right_label: str = "Production") -> CompareResult:
    result = CompareResult()
    result.left_summary = {"label": left_label}
    result.right_summary = {"label": right_label}

    if not left_xml.strip() or not right_xml.strip():
        result.error = "Both metadata inputs are required."
        return result

    try:
        left = parse_facts(left_xml)
    except (etree.XMLSyntaxError, ValueError) as e:
        result.error = f"Left ({left_label}): {e}"
        return result
    try:
        right = parse_facts(right_xml)
    except (etree.XMLSyntaxError, ValueError) as e:
        result.error = f"Right ({right_label}): {e}"
        return result

    result.left_summary.update(_summary(left))
    result.right_summary.update(_summary(right))

    # entityID -----------------------------------------------------------
    if left["entityID"] != right["entityID"]:
        result.diffs.append(DiffItem(
            field="entityID",
            severity=FIELD_SEVERITY["entityID"],
            left=left["entityID"],
            right=right["entityID"],
            note="Different entityIDs mean these are two distinct applications — not a staging/prod pair of the same one. Confirm this is intentional.",
        ))

    # role ---------------------------------------------------------------
    if left["role"] != right["role"]:
        result.diffs.append(DiffItem(
            field="role",
            severity=FIELD_SEVERITY["role"],
            left=left["role"],
            right=right["role"],
            note="One side is an IdP, the other an SP. Comparing across roles is rarely meaningful.",
        ))

    # certs --------------------------------------------------------------
    left_fps = {c.get("fingerprint") for c in left["certs"]}
    right_fps = {c.get("fingerprint") for c in right["certs"]}
    if left_fps != right_fps:
        result.diffs.append(DiffItem(
            field="cert_fingerprints",
            severity=FIELD_SEVERITY["cert_fingerprints"],
            left=sorted(left_fps),
            right=sorted(right_fps),
            note="Signing/encryption certificates differ. Common during rotation — confirm the relying party trusts both, or expect signature-verification failures.",
        ))

    left_expiries = sorted([c.get("not_after") for c in left["certs"] if c.get("not_after")])
    right_expiries = sorted([c.get("not_after") for c in right["certs"] if c.get("not_after")])
    if left_expiries != right_expiries:
        # Only surface if at least one side has < 60 days left
        now = datetime.now(timezone.utc)
        nearest = []
        for e in left_expiries + right_expiries:
            try:
                d = (datetime.fromisoformat(e) - now).days
                nearest.append(d)
            except Exception:
                pass
        if nearest and min(nearest) < 60:
            result.diffs.append(DiffItem(
                field="cert_expiries",
                severity="medium" if min(nearest) < 30 else "info",
                left=left_expiries,
                right=right_expiries,
                note=f"Cert expiries differ; nearest is in {min(nearest)} days. Coordinate rotation across environments to avoid a one-side outage.",
            ))

    left_bits = sorted({c.get("key_bits") for c in left["certs"] if c.get("key_bits")})
    right_bits = sorted({c.get("key_bits") for c in right["certs"] if c.get("key_bits")})
    if left_bits != right_bits:
        result.diffs.append(DiffItem(
            field="cert_key_bits",
            severity=FIELD_SEVERITY["cert_key_bits"],
            left=left_bits,
            right=right_bits,
            note="Key sizes differ between environments. If one side is < 2048 bits, modern verifiers may reject it under hardened policies.",
        ))

    # endpoints ----------------------------------------------------------
    for ep_kind in ("SingleSignOnService", "AssertionConsumerService", "SingleLogoutService"):
        l = _endpoint_set(left["endpoints"][ep_kind])
        r = _endpoint_set(right["endpoints"][ep_kind])
        if l != r:
            result.diffs.append(DiffItem(
                field=f"endpoints.{ep_kind}",
                severity=FIELD_SEVERITY[f"endpoints.{ep_kind}"],
                left=sorted(l),
                right=sorted(r),
                note=f"{ep_kind} endpoints differ. This is almost always the root cause when staging works and prod doesn't.",
            ))

    # NameID -------------------------------------------------------------
    if left["nameid_formats"] != right["nameid_formats"]:
        result.diffs.append(DiffItem(
            field="nameid_formats",
            severity=FIELD_SEVERITY["nameid_formats"],
            left=left["nameid_formats"],
            right=right["nameid_formats"],
            note="NameIDFormat mismatch — staging vs prod will map identities differently. Frequent cause of 'wrong user logged in' tickets.",
        ))

    # Algorithms ---------------------------------------------------------
    if left["signing_algorithms"] != right["signing_algorithms"]:
        result.diffs.append(DiffItem(
            field="signing_algorithms",
            severity=FIELD_SEVERITY["signing_algorithms"],
            left=left["signing_algorithms"],
            right=right["signing_algorithms"],
            note="Advertised SigningMethods diverge. Verify the peer side supports the intersection.",
        ))
    if left["digest_algorithms"] != right["digest_algorithms"]:
        result.diffs.append(DiffItem(
            field="digest_algorithms",
            severity=FIELD_SEVERITY["digest_algorithms"],
            left=left["digest_algorithms"],
            right=right["digest_algorithms"],
            note="Advertised DigestMethods diverge.",
        ))

    # Signing posture ----------------------------------------------------
    for flag in ("AuthnRequestsSigned", "WantAssertionsSigned", "WantAuthnRequestsSigned"):
        if left[flag] != right[flag] and (left[flag] is not None or right[flag] is not None):
            result.diffs.append(DiffItem(
                field=flag,
                severity=FIELD_SEVERITY[flag],
                left=left[flag],
                right=right[flag],
                note=f"{flag} differs. Production should generally be the stricter setting.",
            ))

    # Attributes ---------------------------------------------------------
    if left["attributes"] != right["attributes"]:
        result.diffs.append(DiffItem(
            field="attributes",
            severity=FIELD_SEVERITY["attributes"],
            left=left["attributes"],
            right=right["attributes"],
            note="Released attribute set differs — downstream apps may receive different claims in each environment.",
        ))

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "info": 3, "low": 4}
    result.diffs.sort(key=lambda d: sev_order.get(d.severity, 99))

    return result
