from dataclasses import dataclass, field, asdict
from typing import Optional


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "ok": 5}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    detail: str
    suggestion: str = ""
    evidence: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LintResult:
    kind: str
    summary: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    error: Optional[str] = None

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def sorted_findings(self) -> list:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "error": self.error,
        }
