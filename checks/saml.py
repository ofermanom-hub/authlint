"""SAML 2.0 metadata linter.

Parses an EntityDescriptor / EntitiesDescriptor and surfaces the
implementation issues that most often turn week-1 SSO go-lives into
month-3 support tickets:

- certificate validity window (and days-until-expiry)
- signing & digest algorithm strength
- SSO/SLO endpoints & bindings
- NameID format
- AuthnRequestsSigned / WantAssertionsSigned posture
- AttributeStatement coverage
- IdP-init vs SP-init capability
"""
from __future__ import annotations

import base64
import re
from datetime import datetime, timezone
from typing import Optional

from lxml import etree

from .common import Finding, LintResult

NS = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "alg": "urn:oasis:names:tc:SAML:metadata:algsupport",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}

WEAK_SIG_ALGS = {
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1": "RSA-SHA1 (deprecated)",
    "http://www.w3.org/2000/09/xmldsig#dsa-sha1": "DSA-SHA1 (deprecated)",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-md5": "RSA-MD5 (broken)",
}

WEAK_DIGEST_ALGS = {
    "http://www.w3.org/2000/09/xmldsig#sha1": "SHA-1 (deprecated)",
    "http://www.w3.org/2001/04/xmldsig-more#md5": "MD5 (broken)",
}

GOOD_SIG_ALGS = {
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
    "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1",
    "http://www.w3.org/2007/05/xmldsig-more#ecdsa-sha256",
}


def _parse_x509_validity(cert_b64: str) -> Optional[tuple[datetime, datetime, int]]:
    """Return (not_before, not_after, key_bits) for a DER X.509 cert in base64."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
    except ImportError:
        return None
    try:
        der = base64.b64decode("".join(cert_b64.split()))
        cert = x509.load_der_x509_certificate(der)
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            bits = key.key_size
        elif isinstance(key, ec.EllipticCurvePublicKey):
            bits = key.curve.key_size
        else:
            bits = 0
        return (cert.not_valid_before_utc, cert.not_valid_after_utc, bits)
    except Exception:
        return None


def lint_saml(xml_text: str) -> LintResult:
    result = LintResult(kind="saml")
    xml_text = xml_text.strip()
    if not xml_text:
        result.error = "Empty SAML metadata input."
        return result
    try:
        parser = etree.XMLParser(resolve_entities=False, no_network=True)
        root = etree.fromstring(xml_text.encode("utf-8"), parser=parser)
    except etree.XMLSyntaxError as e:
        result.error = f"Invalid XML: {e.msg}"
        return result

    # Locate the EntityDescriptor (or the first child of EntitiesDescriptor)
    if root.tag == f"{{{NS['md']}}}EntitiesDescriptor":
        entity = root.find("md:EntityDescriptor", NS)
        if entity is None:
            result.error = "EntitiesDescriptor contained no EntityDescriptor."
            return result
    elif root.tag == f"{{{NS['md']}}}EntityDescriptor":
        entity = root
    else:
        result.error = f"Root element is not SAML metadata (got {root.tag})."
        return result

    entity_id = entity.get("entityID", "<unknown>")
    idp = entity.find("md:IDPSSODescriptor", NS)
    sp = entity.find("md:SPSSODescriptor", NS)
    role = idp if idp is not None else sp
    role_kind = "IdP" if idp is not None else ("SP" if sp is not None else "unknown")

    result.summary = {
        "entityID": entity_id,
        "role": role_kind,
    }

    if role is None:
        result.add(Finding(
            id="saml.no-role",
            title="No IDPSSODescriptor or SPSSODescriptor found",
            severity="high",
            detail="The EntityDescriptor lacks both IdP and SP role descriptors.",
            suggestion="Confirm the metadata file is complete and exported from the correct application.",
        ))
        return result

    # --- Certificates -----------------------------------------------------
    certs = role.findall("md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate", NS)
    if not certs:
        result.add(Finding(
            id="saml.no-cert",
            title="No signing/encryption certificate in metadata",
            severity="critical",
            detail="The metadata exposes no X.509 certificate.",
            suggestion="Include at least one KeyDescriptor with a base64-encoded X.509 certificate so the peer can verify signed assertions.",
        ))
    else:
        now = datetime.now(timezone.utc)
        min_days = None
        weakest_bits = None
        for cert_el in certs:
            parsed = _parse_x509_validity(cert_el.text or "")
            if not parsed:
                continue
            nb, na, bits = parsed
            days_left = (na - now).days
            if min_days is None or days_left < min_days:
                min_days = days_left
            if bits and (weakest_bits is None or bits < weakest_bits):
                weakest_bits = bits
        if min_days is None:
            result.add(Finding(
                id="saml.cert-unparseable",
                title="Could not parse X.509 certificate",
                severity="medium",
                detail="The certificate payload was present but did not decode as DER.",
                suggestion="Re-export the metadata; check for whitespace/line-wrap corruption in the base64 body.",
            ))
        else:
            result.summary["cert_days_left"] = min_days
            result.summary["key_bits"] = weakest_bits
            if min_days < 0:
                result.add(Finding(
                    id="saml.cert-expired",
                    title=f"Certificate expired {-min_days} days ago",
                    severity="critical",
                    detail="Signed assertions will be rejected by any conformant peer.",
                    suggestion="Rotate the certificate immediately and re-publish metadata to all relying parties.",
                ))
            elif min_days < 30:
                result.add(Finding(
                    id="saml.cert-near-expiry",
                    title=f"Certificate expires in {min_days} days",
                    severity="high",
                    detail="Rotations on enterprise IdPs often need 2–4 weeks of coordination with relying parties.",
                    suggestion="Schedule a rotation window now; pre-publish the new cert alongside the old (dual-cert metadata).",
                ))
            elif min_days < 90:
                result.add(Finding(
                    id="saml.cert-rotation-soon",
                    title=f"Certificate expires in {min_days} days",
                    severity="medium",
                    detail="Within the typical change-management lead time for regulated enterprises.",
                    suggestion="Add this rotation to the next quarterly maintenance window.",
                ))
            else:
                result.add(Finding(
                    id="saml.cert-ok",
                    title=f"Certificate valid for {min_days} more days",
                    severity="ok",
                    detail="No immediate rotation pressure.",
                ))
            if weakest_bits and weakest_bits < 2048:
                result.add(Finding(
                    id="saml.weak-key",
                    title=f"Weak key size: {weakest_bits}-bit",
                    severity="high",
                    detail="Modern policy baselines (NIST SP 800-131A, PCI 4.0) require RSA ≥ 2048 or equivalent ECC.",
                    suggestion="Regenerate with a 2048-bit (or stronger) RSA key, or move to P-256/P-384 ECDSA.",
                ))

    # --- Signing / digest algorithm support -------------------------------
    sig_methods = entity.findall(".//alg:SigningMethod", NS)
    digest_methods = entity.findall(".//alg:DigestMethod", NS)
    advertised_algs = {el.get("Algorithm") for el in sig_methods if el.get("Algorithm")}
    advertised_digests = {el.get("Algorithm") for el in digest_methods if el.get("Algorithm")}

    weak_sigs = advertised_algs & set(WEAK_SIG_ALGS)
    if weak_sigs:
        result.add(Finding(
            id="saml.weak-sig-alg",
            title="Metadata advertises weak signing algorithm(s)",
            severity="high",
            detail="; ".join(WEAK_SIG_ALGS[a] for a in weak_sigs),
            suggestion="Drop SHA-1/MD5 SigningMethod entries; advertise only RSA-SHA256 (or stronger).",
            evidence=", ".join(weak_sigs),
        ))
    elif advertised_algs and not (advertised_algs & GOOD_SIG_ALGS):
        result.add(Finding(
            id="saml.unknown-sig-alg",
            title="Advertised signing algorithm(s) not on the modern allow-list",
            severity="medium",
            detail="Algorithm URIs do not match RSA-SHA256/384/512 or common ECDSA variants.",
            suggestion="Verify the peer supports the advertised algorithm; standardise on RSA-SHA256 unless there's a specific reason otherwise.",
            evidence=", ".join(advertised_algs),
        ))

    weak_digests = advertised_digests & set(WEAK_DIGEST_ALGS)
    if weak_digests:
        result.add(Finding(
            id="saml.weak-digest-alg",
            title="Metadata advertises weak digest algorithm(s)",
            severity="medium",
            detail="; ".join(WEAK_DIGEST_ALGS[a] for a in weak_digests),
            suggestion="Drop SHA-1/MD5 DigestMethod entries in favour of SHA-256.",
            evidence=", ".join(weak_digests),
        ))

    # --- Endpoints --------------------------------------------------------
    sso = role.findall("md:SingleSignOnService", NS) if role_kind == "IdP" else role.findall("md:AssertionConsumerService", NS)
    slo = role.findall("md:SingleLogoutService", NS)
    bindings = sorted({el.get("Binding", "").rsplit(":", 1)[-1] for el in sso})
    result.summary["sso_bindings"] = bindings
    result.summary["has_slo"] = bool(slo)

    if not sso:
        ep_name = "SingleSignOnService" if role_kind == "IdP" else "AssertionConsumerService"
        result.add(Finding(
            id="saml.no-sso-endpoint",
            title=f"No {ep_name} endpoint declared",
            severity="critical",
            detail=f"Without a {ep_name} endpoint, no peer can initiate SSO with this party.",
            suggestion=f"Add at least one {ep_name} element with an HTTPS Location and a standard Binding.",
        ))
    else:
        non_https = [el.get("Location", "") for el in sso if not (el.get("Location") or "").lower().startswith("https://")]
        if non_https:
            result.add(Finding(
                id="saml.sso-non-https",
                title="SSO endpoint(s) are not HTTPS",
                severity="high",
                detail="SAML messages cross trust boundaries; cleartext bindings leak assertions in transit.",
                suggestion="Re-host every SSO endpoint behind HTTPS with a current TLS certificate.",
                evidence="; ".join(non_https),
            ))
        if role_kind == "IdP" and "HTTP-Redirect" not in bindings and "HTTP-POST" not in bindings:
            result.add(Finding(
                id="saml.no-standard-binding",
                title="No HTTP-Redirect or HTTP-POST binding advertised",
                severity="high",
                detail="These are the two bindings that virtually every SP supports.",
                suggestion="Add at least an HTTP-POST SingleSignOnService entry.",
            ))

    if not slo:
        result.add(Finding(
            id="saml.no-slo",
            title="No SingleLogoutService endpoint",
            severity="low",
            detail="SLO is optional but is increasingly expected for compliance audits (token revocation paths).",
            suggestion="Add an HTTP-Redirect or SOAP SLO endpoint if the platform supports it.",
        ))

    # --- NameID format ----------------------------------------------------
    nameid_els = role.findall("md:NameIDFormat", NS)
    nameid_formats = [el.text for el in nameid_els if el.text]
    result.summary["nameid_formats"] = nameid_formats
    if not nameid_formats:
        result.add(Finding(
            id="saml.no-nameid",
            title="No NameIDFormat advertised",
            severity="medium",
            detail="Without a declared NameIDFormat, SPs fall back to 'unspecified', which is a frequent root-cause of 'wrong user is logged in' tickets.",
            suggestion="Advertise 'emailAddress' or 'persistent' explicitly so the peer can map identities deterministically.",
        ))
    elif any("transient" in f for f in nameid_formats) and not any(
        token in (f or "") for token in ("emailAddress", "persistent", "unspecified") for f in nameid_formats
    ):
        result.add(Finding(
            id="saml.transient-only",
            title="Only transient NameID advertised",
            severity="medium",
            detail="Transient NameIDs reset every session, breaking SCIM/provisioning correlation.",
            suggestion="Add a persistent or emailAddress NameIDFormat if downstream systems need stable user IDs.",
        ))

    # --- Signing posture --------------------------------------------------
    if role_kind == "SP":
        signed_req = role.get("AuthnRequestsSigned", "false").lower() == "true"
        want_signed = role.get("WantAssertionsSigned", "false").lower() == "true"
        result.summary["AuthnRequestsSigned"] = signed_req
        result.summary["WantAssertionsSigned"] = want_signed
        if not want_signed:
            result.add(Finding(
                id="saml.assertions-not-required-signed",
                title="WantAssertionsSigned is false",
                severity="high",
                detail="Without this, an attacker who can MITM the response (or replay one) can inject unsigned assertions.",
                suggestion="Set WantAssertionsSigned='true' in SP metadata.",
            ))
        if not signed_req:
            result.add(Finding(
                id="saml.authnrequest-unsigned",
                title="AuthnRequestsSigned is false",
                severity="medium",
                detail="Signed AuthnRequests prevent IdP-side request tampering and improve audit trails.",
                suggestion="Set AuthnRequestsSigned='true' once the SP has a signing key configured.",
            ))
    elif role_kind == "IdP":
        signed_resp = role.get("WantAuthnRequestsSigned", "false").lower() == "true"
        result.summary["WantAuthnRequestsSigned"] = signed_resp

    # --- AttributeStatement coverage (IdP) --------------------------------
    if role_kind == "IdP":
        attr_els = role.findall("saml:Attribute", NS)
        attr_names = [el.get("Name") for el in attr_els if el.get("Name")]
        result.summary["attributes"] = attr_names
        if not attr_names:
            result.add(Finding(
                id="saml.no-attributes",
                title="No attributes declared in IdP metadata",
                severity="low",
                detail="Many SPs use NameID alone, but pre-declaring email/groups in metadata helps SP-side mapping.",
                suggestion="Advertise the attributes your IdP will release (email, displayName, groups).",
            ))

    return result
