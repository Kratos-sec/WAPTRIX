"""Registry of all passive audit checks."""

from __future__ import annotations

from app.checks.base import AuditContext, PassiveCheck
from app.checks.client_forms import ClientFormsCheck
from app.checks.cookies import CookieCheck
from app.checks.cors_cache import CorsCacheCheck
from app.checks.disclosure import DisclosureCheck
from app.checks.headers import SecurityHeadersCheck
from app.checks.metadata import MetadataCheck
from app.checks.transport_tls import TransportTLSCheck

ALL_CHECKS: tuple[type[PassiveCheck], ...] = (
    SecurityHeadersCheck,
    TransportTLSCheck,
    CookieCheck,
    CorsCacheCheck,
    DisclosureCheck,
    ClientFormsCheck,
    MetadataCheck,
)


def default_checks() -> list[PassiveCheck]:
    return [cls() for cls in ALL_CHECKS]


__all__ = ["ALL_CHECKS", "AuditContext", "PassiveCheck", "default_checks"]
