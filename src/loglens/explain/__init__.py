"""Explanation engine: YAML rule packs turn log entries into plain-language explanations."""

from __future__ import annotations

from loglens.explain.engine import ExplanationEngine
from loglens.explain.rules import DEFAULT_RULES_DIR, LoadIssue, Pack, Rule, RuleSet, load_rules

__all__ = [
    "DEFAULT_RULES_DIR",
    "ExplanationEngine",
    "LoadIssue",
    "Pack",
    "Rule",
    "RuleSet",
    "load_rules",
]
