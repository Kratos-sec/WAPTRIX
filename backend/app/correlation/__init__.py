"""Cross-tool correlation: knowledge-base enrichment and the weighted voting model (paper Section III-D)."""

from __future__ import annotations

from app.correlation.knowledge_base import enrich
from app.correlation.voting import CorrelationOutcome, canonical_key, correlate

__all__ = ["correlate", "CorrelationOutcome", "canonical_key", "enrich"]
