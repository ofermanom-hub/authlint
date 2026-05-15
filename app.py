"""AuthLint — Flask app entrypoint."""
from __future__ import annotations

import os
import re

from flask import Flask, jsonify, render_template, request

from checks import lint_jwt, lint_oidc, lint_saml
from claude_explainer import explain

app = Flask(__name__)


def _detect_kind(text: str) -> str:
    s = text.strip()
    if not s:
        return ""
    if s.lower().startswith(("http://", "https://")) or "/.well-known/" in s:
        return "oidc"
    if s.startswith("<") or "<EntityDescriptor" in s or "<md:EntityDescriptor" in s:
        return "saml"
    if re.fullmatch(r"[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)?", s):
        return "jwt"
    return ""


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/scan")
def scan():
    kind = (request.form.get("kind") or "").strip().lower()
    payload = request.form.get("payload", "")
    if kind in ("", "auto"):
        kind = _detect_kind(payload)
    if kind == "saml":
        result = lint_saml(payload)
    elif kind == "jwt":
        result = lint_jwt(payload)
    elif kind == "oidc":
        result = lint_oidc(payload)
    else:
        return render_template(
            "_result.html",
            result={
                "kind": "unknown",
                "summary": {},
                "findings": [],
                "error": "Could not auto-detect input. Paste SAML XML, a JWT (header.payload.signature), or an OIDC issuer/discovery URL.",
            },
        )
    return render_template("_result.html", result=result.to_dict())


@app.post("/explain")
def explain_finding():
    kind = request.form.get("kind", "")
    finding = {
        "id": request.form.get("id", ""),
        "title": request.form.get("title", ""),
        "detail": request.form.get("detail", ""),
    }
    text = explain(kind, finding)
    if not text:
        text = "Claude explainer not configured — set ANTHROPIC_API_KEY to enable."
    return f'<div class="mt-2 text-sm italic text-slate-600">{text}</div>'


@app.post("/api/scan")
def api_scan():
    """JSON API — handy for portfolio demos and CLI users."""
    data = request.get_json(silent=True) or {}
    kind = (data.get("kind") or "").lower()
    payload = data.get("payload", "")
    if kind in ("", "auto"):
        kind = _detect_kind(payload)
    if kind == "saml":
        result = lint_saml(payload)
    elif kind == "jwt":
        result = lint_jwt(payload)
    elif kind == "oidc":
        result = lint_oidc(payload)
    else:
        return jsonify({"error": "unknown kind"}), 400
    return jsonify(result.to_dict())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5050")), debug=True)
