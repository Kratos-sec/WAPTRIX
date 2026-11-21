"""Cross-tool correlation and the weighted-agreement confidence model (paper Section III-D, eq. 1).

Pipeline per subdomain:
  1. Reduce raw findings (built-in checks + every tool) to canonical groups. Findings sharing a canonical
     key — normalised endpoint, injection point and class — are reports of the same underlying defect.
  2. For each group compute the confidence

         C(f) = ( Σ_{i∈T} w_i·s_i(f) ) / ( Σ_{i∈E} w_i·a_i(f) )  +  γ·v(f)

     where T is the set of engines that reported the finding, E the set of engines *capable* of the
     finding's class that actually ran on the host (so silence of an inapplicable engine never penalises
     it), w_i the engine's reliability weight, s_i its normalised certainty, v(f) whether an active
     confirmation adapter reproduced it and γ the confirmation bonus.
  3. Enrich the surviving representative through the knowledge base and admit it when C(f) ≥ τ. Findings
     below τ are not discarded: they are returned in a re-test queue for Stage S3's bounded retry loop.

The special cases τ→0 and τ→1 under uniform weights recover the union and intersection heuristics of
prior multi-scanner work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

from app.correlation import profiles
from app.correlation.knowledge_base import enrich
from app.models.finding import CorrelationInfo, PassiveFinding

CanonicalKey = tuple[str, str, str, str]


@dataclass
class CorrelationOutcome:
    admitted: list[PassiveFinding] = field(default_factory=list)
    queued: list[PassiveFinding] = field(default_factory=list)

    @property
    def findings(self) -> list[PassiveFinding]:
        return [*self.admitted, *self.queued]


def _endpoint(url: str) -> str:
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{host}{port}{parts.path or '/'}"


def _injection_point(url: str) -> str:
    return ",".join(sorted(key for key, _ in parse_qsl(urlsplit(url).query)))


def _evidence_sig(finding: PassiveFinding) -> str:
    return " ".join(finding.evidence.lower().split())


def _class(finding: PassiveFinding) -> str:
    """The CWE-class component of the key.

    Built-in rules key on their rule id: several distinct rules share a CWE (e.g. CWE-319 covers eight),
    so collapsing by CWE would merge unrelated issues. A rule flagged multi-instance (one row per
    vulnerable library) adds its evidence so genuine repeats stay apart. Tool-only alerts have no WAPTrix
    rule, so they key on the CWE class itself — this is what lets a confirmation adapter (sqlmap) merge
    with, and lift, a scanner's candidate (wapiti) for the same defect on the same injection point.
    """
    if finding.rule_id in profiles.MULTI_INSTANCE_RULES:
        return f"{finding.rule_id}|{_evidence_sig(finding)}"
    if profiles.is_builtin_rule(finding.rule_id):
        return profiles.EQUIVALENT_RULES.get(finding.rule_id, finding.rule_id)
    return f"cwe:{finding.cwe or finding.rule_id}"


def canonical_key(finding: PassiveFinding) -> CanonicalKey:
    """Endpoint + injection point + class (paper Section III-D)."""
    return (finding.subdomain, _endpoint(finding.url), _injection_point(finding.url), _class(finding))


def _pick_representative(group: list[PassiveFinding]) -> PassiveFinding:
    return max(group, key=lambda f: (f.severity.rank, profiles.certainty(f.confidence.value), len(f.sources)))


def _merge_into(rep: PassiveFinding, group: list[PassiveFinding]) -> PassiveFinding:
    """Union the corroborating engines onto the representative. Call only after scoring: it rewrites
    ``rep.sources``, which the per-engine certainty in :func:`_score` must read unmutated first."""
    sources: list[str] = []
    tool_refs: list[str] = []
    owasp: list[str] = []
    references: list[str] = []
    for f in group:
        sources += f.sources
        tool_refs += f.tool_refs
        owasp += f.owasp
        references += f.references
    rep.sources = list(dict.fromkeys(sources))
    rep.tool_refs = list(dict.fromkeys(tool_refs))
    rep.owasp = list(dict.fromkeys(owasp)) or rep.owasp
    rep.references = list(dict.fromkeys(references))
    if rep.cvss_vector is None:
        with_vector = next((f for f in group if f.cvss_vector is not None), None)
        if with_vector is not None:
            rep.cvss_vector, rep.cvss_score = with_vector.cvss_vector, with_vector.cvss_score
    return rep


def _score(group: list[PassiveFinding], tag: str, engines_ran: set[str],
           tau: float, gamma: float) -> CorrelationInfo:

    # s_i per detecting engine: strongest certainty that engine reported anywhere in the group.
    detector_certainty: dict[str, float] = {}
    for f in group:
        s = profiles.certainty(f.confidence.value)
        for engine in f.sources:
            detector_certainty[engine] = max(detector_certainty.get(engine, 0.0), s)
    detectors = set(detector_certainty)

    # E: engines that ran and are capable of this class, plus any engine that actually detected it.
    applicable = {e for e in engines_ran if tag in profiles.detects(e)} | detectors

    numerator = sum(profiles.weight(e) * detector_certainty[e] for e in detectors)
    denominator = sum(profiles.weight(e) for e in applicable) or 1.0
    confirmed = any(profiles.confirms(e, tag) for e in detectors)
    score = numerator / denominator + (gamma if confirmed else 0.0)
    score = round(min(score, 1.0), 4)

    return CorrelationInfo(
        score=score,
        threshold=tau,
        admitted=score >= tau,
        confirmed=confirmed,
        tag=tag,
        detectors=sorted(detectors),
        applicable=sorted(applicable),
        silent=sorted(applicable - detectors),
    )


def correlate(findings: list[PassiveFinding], engines_ran: set[str]) -> CorrelationOutcome:
    """De-duplicate, vote and enrich. ``engines_ran`` is every engine that executed on the host."""
    tau, gamma = profiles.tau(), profiles.gamma()

    groups: dict[CanonicalKey, list[PassiveFinding]] = {}
    for finding in findings:
        groups.setdefault(canonical_key(finding), []).append(finding)

    outcome = CorrelationOutcome()
    for group in groups.values():
        rep = _pick_representative(group)
        tag = profiles.tag_for(rep.rule_id, rep.cwe or None)
        info = _score(group, tag, engines_ran, tau, gamma)  # reads per-engine certainty before any merge
        _merge_into(rep, group)
        rep.correlation = info
        rep.correlation_score = info.score
        enrich(rep)
        (outcome.admitted if info.admitted else outcome.queued).append(rep)
    return outcome


__all__ = ["correlate", "CorrelationOutcome", "canonical_key"]
