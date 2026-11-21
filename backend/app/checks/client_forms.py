"""Client-side hygiene: form transport, anti-CSRF token patterns, SRI and vulnerable JS library fingerprinting."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from bs4 import Tag

from app.checks.base import AuditContext, PassiveCheck
from app.models.finding import PassiveFinding

CSRF_FIELD = re.compile(
    r"(csrf|xsrf|_token$|^token$|authenticity_token|__requestverificationtoken|anti.?forgery|nonce|"
    r"form_key|formkey|_wpnonce|__viewstategenerator|state$)",
    re.IGNORECASE,
)
MULTI_PART_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.in", "co.jp", "com.br", "co.nz", "com.sg"}


def site_of(host: str) -> str:
    """Approximate registrable domain (eTLD+1) used to distinguish first- and third-party origins."""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _version_tuple(version: str) -> tuple[int, int, int]:
    parts = [int(p) for p in re.findall(r"\d+", version)[:3]]
    parts += [0] * (3 - len(parts))
    return parts[0], parts[1], parts[2]


@dataclass(frozen=True)
class VulnRange:
    introduced: str
    fixed: str
    advisory: str

    def contains(self, version: str) -> bool:
        v = _version_tuple(version)
        return _version_tuple(self.introduced) <= v < _version_tuple(self.fixed)


@dataclass(frozen=True)
class LibrarySignature:
    name: str
    aliases: tuple[str, ...]
    ranges: tuple[VulnRange, ...]

    def patterns(self) -> list[re.Pattern[str]]:
        ver = r"v?(\d+\.\d+(?:\.\d+)?)"
        out: list[re.Pattern[str]] = []
        for alias in self.aliases:
            a = re.escape(alias)
            out.append(re.compile(rf"(?:^|/){a}[-.]{ver}(?:\.slim)?(?:\.min)?\.js(?:$|[?#])", re.I))
            out.append(re.compile(rf"/{a}/{ver}/", re.I))
            out.append(re.compile(rf"(?:^|/){a}@{ver}(?:/|$)", re.I))
        return out

    def match(self, url: str) -> str | None:
        target = url.split("#", 1)[0]
        for pattern in self.patterns():
            m = pattern.search(target)
            if m:
                return m.group(1)
        return None


VULNERABLE_LIBRARIES: tuple[LibrarySignature, ...] = (
    LibrarySignature(
        "jQuery",
        ("jquery",),
        (
            VulnRange("0.0.0", "3.5.0", "CVE-2020-11022 / CVE-2020-11023: XSS via htmlPrefilter (fixed in 3.5.0)"),
        ),
    ),
    LibrarySignature(
        "jQuery UI",
        ("jquery-ui", "jqueryui"),
        (VulnRange("0.0.0", "1.13.2", "CVE-2021-41184 / CVE-2022-31160: XSS in widget options (fixed in 1.13.2)"),),
    ),
    LibrarySignature(
        "AngularJS",
        ("angular", "angular.js", "angularjs"),
        (
            VulnRange(
                "1.0.0",
                "2.0.0",
                "AngularJS 1.x is end-of-life (Dec 2021); CVE-2022-25869, CVE-2024-21490 remain unpatched",
            ),
        ),
    ),
    LibrarySignature(
        "Bootstrap",
        ("bootstrap", "twitter-bootstrap"),
        (
            VulnRange("0.0.0", "3.4.1", "CVE-2019-8331 / CVE-2018-14041: XSS in tooltip/data-target (fixed in 3.4.1)"),
            VulnRange("4.0.0", "4.3.1", "CVE-2019-8331: XSS in tooltip/popover data-template (fixed in 4.3.1)"),
        ),
    ),
    LibrarySignature(
        "Lodash",
        ("lodash", "lodash.js"),
        (VulnRange("0.0.0", "4.17.21", "CVE-2021-23337 / CVE-2020-8203: command injection & prototype pollution (fixed in 4.17.21)"),),
    ),
    LibrarySignature(
        "Moment.js",
        ("moment", "moment.js"),
        (VulnRange("0.0.0", "2.29.4", "CVE-2022-31129: ReDoS in RFC 2822 parsing (fixed in 2.29.4)"),),
    ),
    LibrarySignature(
        "Handlebars",
        ("handlebars", "handlebars.js"),
        (VulnRange("0.0.0", "4.7.7", "CVE-2021-23369 / CVE-2021-23383: RCE via template compilation (fixed in 4.7.7)"),),
    ),
    LibrarySignature(
        "Underscore.js",
        ("underscore", "underscore.js"),
        (VulnRange("1.3.2", "1.12.1", "CVE-2021-23358: arbitrary code execution via template (fixed in 1.12.1)"),),
    ),
    LibrarySignature(
        "Vue.js",
        ("vue",),
        (VulnRange("2.0.0", "3.0.0", "Vue 2 reached end-of-life on 2023-12-31; CVE-2024-6783 / CVE-2024-9506 unpatched"),),
    ),
    LibrarySignature(
        "DOMPurify",
        ("dompurify", "purify"),
        (
            VulnRange("0.0.0", "2.5.4", "CVE-2024-45801: depth-check bypass / prototype pollution (fixed in 2.5.4)"),
            VulnRange("3.0.0", "3.1.3", "CVE-2024-45801: depth-check bypass (fixed in 3.1.3)"),
        ),
    ),
    LibrarySignature(
        "Axios",
        ("axios",),
        (VulnRange("0.8.1", "1.8.2", "CVE-2023-45857 / CVE-2025-27152: XSRF token leakage and SSRF via absolute URLs (fixed in 1.8.2)"),),
    ),
)


def fingerprint_library(url: str) -> list[tuple[str, str, str]]:
    """Return (library, version, advisory) tuples for vulnerable versions referenced by a script URL."""
    hits: list[tuple[str, str, str]] = []
    for lib in VULNERABLE_LIBRARIES:
        version = lib.match(url)
        if not version:
            continue
        for vuln in lib.ranges:
            if vuln.contains(version):
                hits.append((lib.name, version, vuln.advisory))
                break
    return hits


def _describe_form(form: Tag, action: str) -> str:
    method = str(form.get("method") or "get").upper()
    names = [str(i.get("name")) for i in form.find_all(["input", "select", "textarea"]) if i.get("name")]
    return f"<form method=\"{method}\" action=\"{action}\"> fields: {', '.join(names[:12]) or '(none named)'}"


class ClientFormsCheck(PassiveCheck):
    name = "client_forms"
    rule_ids = (
        "FORM-PASSWORD-OVER-HTTP",
        "FORM-INSECURE-ACTION",
        "FORM-NO-CSRF-TOKEN",
        "FORM-PASSWORD-AUTOCOMPLETE",
        "SRI-MISSING-SCRIPT",
        "SRI-MISSING-STYLESHEET",
        "JS-VULNERABLE-LIBRARY",
    )

    def run(self, ctx: AuditContext) -> list[PassiveFinding]:
        if ctx.soup is None or ctx.primary is None:
            return []
        findings: list[PassiveFinding] = []
        findings.extend(self._forms(ctx))
        findings.extend(self._sri_and_libraries(ctx))
        return findings

    def _forms(self, ctx: AuditContext) -> list[PassiveFinding]:
        assert ctx.soup is not None and ctx.primary is not None
        page_url = ctx.primary.final_url or ctx.primary.url
        page_https = page_url.startswith("https://")
        findings: list[PassiveFinding] = []
        missing_csrf: list[str] = []
        autocomplete: list[str] = []

        for form in ctx.soup.find_all("form"):
            raw_action = str(form.get("action") or "").strip()
            action = urljoin(page_url, raw_action) if raw_action else page_url
            action_scheme = urlsplit(action).scheme.lower()
            passwords = form.find_all("input", attrs={"type": lambda t: t and t.lower() == "password"})
            description = _describe_form(form, raw_action or "(self)")

            if passwords and (not page_https or action_scheme == "http"):
                findings.append(
                    self.finding(
                        ctx,
                        "FORM-PASSWORD-OVER-HTTP",
                        evidence=description,
                        url=page_url,
                        detail=f"Page scheme: {urlsplit(page_url).scheme}; resolved action: {action}",
                    )
                )
            elif page_https and action_scheme == "http":
                findings.append(
                    self.finding(
                        ctx,
                        "FORM-INSECURE-ACTION",
                        evidence=description,
                        url=page_url,
                        detail=f"Resolved action: {action}",
                    )
                )

            method = str(form.get("method") or "get").strip().lower()
            if method == "post":
                hidden = [
                    str(i.get("name") or "")
                    for i in form.find_all("input")
                    if str(i.get("type") or "").lower() == "hidden"
                ]
                if not any(CSRF_FIELD.search(name) for name in hidden):
                    missing_csrf.append(description)

            for field in passwords:
                if field.get("autocomplete") is None:
                    autocomplete.append(f"<input type=\"password\" name=\"{field.get('name') or ''}\">")

        if missing_csrf:
            findings.append(
                self.finding(
                    ctx,
                    "FORM-NO-CSRF-TOKEN",
                    evidence="\n".join(missing_csrf[:5]),
                    url=page_url,
                    detail=f"{len(missing_csrf)} POST form(s) without a recognizable anti-CSRF hidden field.",
                )
            )
        if autocomplete:
            findings.append(
                self.finding(ctx, "FORM-PASSWORD-AUTOCOMPLETE", evidence="\n".join(autocomplete[:5]), url=page_url)
            )
        return findings

    def _sri_and_libraries(self, ctx: AuditContext) -> list[PassiveFinding]:
        assert ctx.soup is not None and ctx.primary is not None
        page_url = ctx.primary.final_url or ctx.primary.url
        own_site = site_of(ctx.target.host)
        findings: list[PassiveFinding] = []
        scripts_without_sri: list[str] = []
        styles_without_sri: list[str] = []
        library_hits: dict[tuple[str, str], tuple[str, str]] = {}

        for script in ctx.soup.find_all("script", src=True):
            src = urljoin(page_url, str(script["src"]).strip())
            for lib, version, advisory in fingerprint_library(src):
                library_hits.setdefault((lib, version), (advisory, src))
            host = urlsplit(src).hostname or ""
            if host and site_of(host) != own_site and not script.get("integrity"):
                scripts_without_sri.append(src)

        for link in ctx.soup.find_all("link", href=True):
            rel = " ".join(link.get("rel") or []).lower()
            if "stylesheet" not in rel:
                continue
            href = urljoin(page_url, str(link["href"]).strip())
            host = urlsplit(href).hostname or ""
            if host and site_of(host) != own_site and not link.get("integrity"):
                styles_without_sri.append(href)

        if scripts_without_sri:
            unique = list(dict.fromkeys(scripts_without_sri))
            findings.append(
                self.finding(
                    ctx,
                    "SRI-MISSING-SCRIPT",
                    evidence="\n".join(unique[:8]),
                    url=page_url,
                    detail=f"{len(unique)} third-party script(s) loaded without an integrity attribute.",
                )
            )
        if styles_without_sri:
            unique = list(dict.fromkeys(styles_without_sri))
            findings.append(
                self.finding(ctx, "SRI-MISSING-STYLESHEET", evidence="\n".join(unique[:8]), url=page_url)
            )
        for (lib, version), (advisory, src) in library_hits.items():
            findings.append(
                self.finding(
                    ctx,
                    "JS-VULNERABLE-LIBRARY",
                    evidence=f"{lib} {version} loaded from {src}",
                    url=page_url,
                    detail=f"Advisory: {advisory}",
                )
            )
        return findings
