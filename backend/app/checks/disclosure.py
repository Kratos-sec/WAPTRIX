"""Information disclosure checks: banners, version headers, stack traces, debug modes, comments, IPs, emails."""

from __future__ import annotations

import ipaddress
import re

from bs4 import Comment

from app.checks.base import AuditContext, PassiveCheck, truncate
from app.engine.fetcher import FetchResult
from app.models.finding import PassiveFinding

SERVER_VERSION = re.compile(r"[A-Za-z][\w.\-]*/\d+(?:\.\d+)+[\w.\-]*")
VERSION_HEADERS = ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-powered-cms")
DEBUG_HEADERS = ("x-debug-token", "x-debug-token-link", "x-symfony-profiler", "x-clockwork-version")

STACK_TRACE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Python traceback", re.compile(r"Traceback \(most recent call last\):")),
    ("Java stack trace", re.compile(r"\bat [a-zA-Z_$][\w$]*(?:\.[\w$<>]+)+\([\w$]+\.java:\d+\)")),
    ("Java exception", re.compile(r"\b(?:java|javax|jakarta)\.[\w.]+(?:Exception|Error)\b(?::|\s+at\b)")),
    (".NET exception", re.compile(r"\bSystem\.[A-Za-z.]+Exception\b[^\n]{0,200}\n?\s*at [\w.]+\(")),
    ("ASP.NET error page", re.compile(r"Server Error in '[^']*' Application")),
    ("PHP error", re.compile(r"(?:Fatal error|Parse error|Warning|Notice|Deprecated)(?:</b>)?:\s.{0,300}? in (?:<b>)?[^<\s]+\.php(?:</b>)? on line (?:<b>)?\d+", re.S)),
    ("PHP stack trace", re.compile(r"Stack trace:\s*(?:<br\s*/?>)?\s*#0 ")),
    ("Node.js stack trace", re.compile(r"\n\s+at (?:[\w.$<>\[\] ]+ )?\(?(?:/[\w.@/-]+|[A-Za-z]:\\[^)\n]+)\.[cm]?js:\d+:\d+\)?")),
    ("Ruby backtrace", re.compile(r"[\w/.-]+\.rb:\d+:in `")),
    ("Go panic", re.compile(r"goroutine \d+ \[running\]:")),
    ("SQL error", re.compile(r"(?:You have an error in your SQL syntax|SQLSTATE\[\w+\]|ORA-\d{5}:|PG::\w+Error|Microsoft OLE DB Provider for SQL Server)")),
]

DEBUG_PAGE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Django DEBUG=True", re.compile(r"You(?:'|&#39;|&#x27;)re seeing this error because you have\s*<code>DEBUG = True</code>")),
    ("Werkzeug interactive debugger", re.compile(r"(?:Werkzeug Debugger|The debugger caught an exception in your WSGI application)")),
    ("Laravel Ignition / Whoops", re.compile(r"(?:Whoops! There was an error\.|window\.ignite|facade/ignition|Illuminate\\\\Foundation)")),
    ("Symfony web profiler toolbar", re.compile(r"(?:sf-toolbar|sfwdt[0-9a-f]{6}|_wdt/[0-9a-f]{6})")),
    ("Rails debug exception page", re.compile(r"Action Controller: Exception caught")),
    ("Xdebug output", re.compile(r"class=['\"]xdebug-error")),
    ("Spring Boot Whitelabel error with trace", re.compile(r"Whitelabel Error Page[\s\S]{0,2000}\bat [\w.$]+\(")),
    ("Express default error handler", re.compile(r"<pre>(?:Error|TypeError|ReferenceError): [^<]+<br> &nbsp; &nbsp;at ")),
]

COMMENT_KEYWORDS = re.compile(
    r"\b(todo|fixme|hack|xxx|bug|password|passwd|pwd|secret|api[_ -]?key|token|credential|"
    r"debug|internal|staging|admin|backdoor|sql|database|private key|disable[d]? (?:auth|security|csrf))\b",
    re.IGNORECASE,
)
PRIVATE_IP = re.compile(
    r"(?<![\d.])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?![\d.]*\d)"
)
EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
EMAIL_FALSE_POSITIVE_SUFFIX = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".js", ".css")


def _excerpt(text: str, match: re.Match[str], radius: int = 160) -> str:
    start = max(0, match.start() - 40)
    end = min(len(text), match.end() + radius)
    return text[start:end]


def find_private_ips(text: str) -> list[str]:
    found: list[str] = []
    for match in PRIVATE_IP.finditer(text):
        candidate = match.group(1)
        try:
            if ipaddress.ip_address(candidate).is_private and candidate not in found:
                found.append(candidate)
        except ValueError:
            continue
    return found


class DisclosureCheck(PassiveCheck):
    name = "disclosure"
    rule_ids = (
        "DISC-SERVER-VERSION",
        "DISC-VERSION-HEADER",
        "DISC-STACK-TRACE",
        "DISC-DEBUG-MODE",
        "DISC-HTML-COMMENTS",
        "DISC-PRIVATE-IP",
        "DISC-EMAIL",
    )

    def run(self, ctx: AuditContext) -> list[PassiveFinding]:
        primary = ctx.primary
        if primary is None:
            return []
        findings: list[PassiveFinding] = []
        findings.extend(self._headers(ctx, primary))
        for response in self._bodies(ctx):
            findings.extend(self._body_errors(ctx, response))
        findings.extend(self._comments(ctx))
        findings.extend(self._private_ips(ctx, primary))
        findings.extend(self._emails(ctx))
        return findings

    @staticmethod
    def _bodies(ctx: AuditContext) -> list[FetchResult]:
        """Primary response plus the HTTP variant when it served different content."""
        bodies = [ctx.primary] if ctx.primary else []
        if ctx.http_ok and ctx.http is not ctx.primary and ctx.http and ctx.http.body:
            if not bodies or ctx.http.body != bodies[0].body:
                bodies.append(ctx.http)
        return [b for b in bodies if b is not None]

    def _headers(self, ctx: AuditContext, response: FetchResult) -> list[PassiveFinding]:
        findings: list[PassiveFinding] = []
        url = response.final_url
        server = response.header("server")
        if server and SERVER_VERSION.search(server):
            findings.append(self.finding(ctx, "DISC-SERVER-VERSION", evidence=f"Server: {server}", url=url))
        disclosed = [f"{name}: {response.header(name)}" for name in VERSION_HEADERS if response.header(name)]
        if disclosed:
            findings.append(self.finding(ctx, "DISC-VERSION-HEADER", evidence="\n".join(disclosed), url=url))
        debug = [f"{name}: {response.header(name)}" for name in DEBUG_HEADERS if response.header(name)]
        if debug:
            findings.append(
                self.finding(
                    ctx,
                    "DISC-DEBUG-MODE",
                    evidence="\n".join(debug),
                    url=url,
                    detail="Debug/profiler response headers indicate developer tooling is enabled.",
                )
            )
        return findings

    def _body_errors(self, ctx: AuditContext, response: FetchResult) -> list[PassiveFinding]:
        body = response.body
        if not body:
            return []
        findings: list[PassiveFinding] = []
        url = response.final_url
        for label, pattern in STACK_TRACE_PATTERNS:
            match = pattern.search(body)
            if match:
                findings.append(
                    self.finding(
                        ctx,
                        "DISC-STACK-TRACE",
                        evidence=_excerpt(body, match),
                        url=url,
                        detail=f"Detected pattern: {label} (HTTP {response.status_code}).",
                    )
                )
                break
        for label, pattern in DEBUG_PAGE_PATTERNS:
            match = pattern.search(body)
            if match:
                findings.append(
                    self.finding(
                        ctx,
                        "DISC-DEBUG-MODE",
                        evidence=_excerpt(body, match),
                        url=url,
                        detail=f"Detected: {label}.",
                    )
                )
                break
        return findings

    def _comments(self, ctx: AuditContext) -> list[PassiveFinding]:
        if ctx.soup is None:
            return []
        hits: list[str] = []
        for comment in ctx.soup.find_all(string=lambda s: isinstance(s, Comment)):
            text = str(comment).strip()
            if not text or text.lower().startswith(("[if", "<![endif", "[endif")):
                continue
            if COMMENT_KEYWORDS.search(text):
                hits.append(f"<!-- {truncate(text, 160)} -->")
        if not hits:
            return []
        return [
            self.finding(
                ctx,
                "DISC-HTML-COMMENTS",
                evidence="\n".join(hits[:6]),
                detail=f"{len(hits)} comment(s) contain sensitive keywords.",
            )
        ]

    def _private_ips(self, ctx: AuditContext, response: FetchResult) -> list[PassiveFinding]:
        if ctx.target.host.replace(".", "").isdigit():
            return []
        header_text = "\n".join(f"{k}: {v}" for k, v in (response.final.headers if response.final else []))
        ips = find_private_ips(header_text) + find_private_ips(response.body)
        unique = list(dict.fromkeys(ips))
        if not unique:
            return []
        return [
            self.finding(
                ctx,
                "DISC-PRIVATE-IP",
                evidence="Private address(es): " + ", ".join(unique[:10]),
                url=response.final_url,
            )
        ]

    def _emails(self, ctx: AuditContext) -> list[PassiveFinding]:
        if ctx.soup is None or ctx.primary is None:
            return []
        candidates = set(EMAIL.findall(ctx.primary.body))
        emails = sorted(e for e in candidates if not e.lower().endswith(EMAIL_FALSE_POSITIVE_SUFFIX))
        if not emails:
            return []
        return [self.finding(ctx, "DISC-EMAIL", evidence=", ".join(emails[:15]))]
