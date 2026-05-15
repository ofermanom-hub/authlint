"""Quick smoke test — run inside the venv.

  .venv/bin/python smoke_test.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap

from checks import diff_saml, lint_jwt, lint_oidc, lint_saml


def _ok(label: str) -> None:
    print(f"  \033[32m✓\033[0m {label}")


def _fail(label: str, details: str = "") -> None:
    print(f"  \033[31m✗\033[0m {label}")
    if details:
        print(textwrap.indent(details, "      "))
    sys.exit(1)


def test_jwt_alg_none() -> None:
    print("JWT — alg:none")
    # eyJhbGciOiJub25lIn0 = {"alg":"none"}
    # eyJzdWIiOiJtZSJ9 = {"sub":"me"}
    token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJtZSJ9."
    r = lint_jwt(token).to_dict()
    ids = {f["id"] for f in r["findings"]}
    if "jwt.alg-none" in ids:
        _ok("flagged alg:none")
    else:
        _fail("missed alg:none", json.dumps(r, indent=2))


def test_jwt_typical() -> None:
    print("JWT — typical (HS256, missing aud/exp)")
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik9mZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.dummysig"
    r = lint_jwt(token).to_dict()
    ids = {f["id"] for f in r["findings"]}
    if "jwt.hmac-alg" in ids:
        _ok("flagged HMAC")
    else:
        _fail("missed HMAC", json.dumps(r, indent=2))
    if "jwt.missing-exp" in ids and "jwt.missing-aud" in ids:
        _ok("flagged missing exp + aud")
    else:
        _fail("did not flag missing standard claims", json.dumps(r, indent=2))


SAML_METADATA = """<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>MIIBszCCARwCCQDxxx</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>"""


def test_saml_basic() -> None:
    print("SAML — minimal IdP with http endpoint")
    r = lint_saml(SAML_METADATA).to_dict()
    ids = {f["id"] for f in r["findings"]}
    if "saml.sso-non-https" in ids:
        _ok("flagged non-HTTPS SSO endpoint")
    else:
        _fail("missed non-HTTPS endpoint", json.dumps(r, indent=2))
    if "saml.no-slo" in ids:
        _ok("flagged missing SLO")
    else:
        _fail("missed missing SLO", json.dumps(r, indent=2))
    if "saml.no-nameid" in ids:
        _ok("flagged missing NameIDFormat")
    else:
        _fail("missed missing NameID", json.dumps(r, indent=2))


def test_oidc_live() -> None:
    print("OIDC — live Google discovery")
    r = lint_oidc("https://accounts.google.com").to_dict()
    if r.get("error"):
        print(f"  ! skipping live test: {r['error']}")
        return
    if r["summary"].get("issuer"):
        _ok(f"fetched issuer {r['summary']['issuer']}")
    else:
        _fail("no issuer", json.dumps(r, indent=2))


SAML_STAGING = """<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://app.example.com">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                   AuthnRequestsSigned="true" WantAssertionsSigned="true">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                              Location="https://staging.example.com/acs"/>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
  </SPSSODescriptor>
</EntityDescriptor>"""

SAML_PROD = """<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://app.example.com">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                   AuthnRequestsSigned="false" WantAssertionsSigned="true">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                              Location="https://prod.example.com/acs"/>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
  </SPSSODescriptor>
</EntityDescriptor>"""


def test_saml_diff() -> None:
    print("SAML diff — staging vs prod")
    r = diff_saml(SAML_STAGING, SAML_PROD).to_dict()
    fields = {d["field"] for d in r["diffs"]}
    if "endpoints.AssertionConsumerService" in fields:
        _ok("flagged ACS endpoint drift")
    else:
        _fail("missed ACS endpoint diff", json.dumps(r, indent=2))
    if "nameid_formats" in fields:
        _ok("flagged NameIDFormat drift")
    else:
        _fail("missed NameIDFormat diff", json.dumps(r, indent=2))
    if "AuthnRequestsSigned" in fields:
        _ok("flagged signing-posture drift")
    else:
        _fail("missed signing-posture diff", json.dumps(r, indent=2))


def test_saml_diff_identical() -> None:
    print("SAML diff — identical inputs")
    r = diff_saml(SAML_STAGING, SAML_STAGING).to_dict()
    if not r["diffs"]:
        _ok("no diffs for identical inputs")
    else:
        _fail("false-positive diffs", json.dumps(r, indent=2))


if __name__ == "__main__":
    test_jwt_alg_none()
    test_jwt_typical()
    test_saml_basic()
    test_oidc_live()
    test_saml_diff()
    test_saml_diff_identical()
    print("\n\033[32mAll smoke checks passed.\033[0m")
