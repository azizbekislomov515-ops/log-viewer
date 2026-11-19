"""JSON Schema for rule packs (``rules/*.yaml``).

A pack is validated in two steps: the pack header first, then every rule on its own, so
one bad rule is reported and skipped while the rest of the pack still loads.
"""

from __future__ import annotations

from typing import Any

from loglens.core.models import Category, Severity

_TEXT: dict[str, Any] = {"type": "string", "minLength": 1}
_TEXT_LIST: dict[str, Any] = {"type": "array", "items": _TEXT, "minItems": 1}
_SCALAR: dict[str, Any] = {"type": ["string", "integer", "boolean"]}
_SEVERITIES = [s.name.lower() for s in Severity]

SELECTOR: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "minProperties": 1,
    "description": "Any criterion matching selects the source (OR). Globs for the first four.",
    "properties": {
        "units": _TEXT_LIST,
        "paths": _TEXT_LIST,
        "images": _TEXT_LIST,
        "services": _TEXT_LIST,
        "parsers": _TEXT_LIST,
        "programs": _TEXT_LIST,
    },
}

_EXPECT: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["text"],
    "properties": {
        "title": _TEXT,
        "text": _TEXT,
        "cause": _TEXT,
        "action": _TEXT,
        "severity": {"enum": _SEVERITIES},
        "category": {"enum": [c.value for c in Category]},
    },
}

_EXAMPLE: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["line", "expect"],
    "properties": {"line": _TEXT, "source": _TEXT, "expect": _EXPECT},
}

_COUNTER_EXAMPLE: dict[str, Any] = {
    "anyOf": [
        _TEXT,
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["line"],
            "properties": {"line": _TEXT, "source": _TEXT},
        },
    ]
}

RULE: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "id",
        "title",
        "template",
        "category",
        "match",
        "examples",
        "counter_examples",
    ],
    "properties": {
        "id": {"type": "string", "pattern": r"^[a-z0-9_]+(\.[a-z0-9_]+)+$"},
        "title": _TEXT,
        "template": _TEXT,
        "cause": _TEXT,
        "action": _TEXT,
        "category": {"enum": [c.value for c in Category]},
        "severity_override": {"enum": _SEVERITIES},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "references": _TEXT_LIST,
        "tags": _TEXT_LIST,
        "applies_to": SELECTOR,
        "match": {
            "type": "object",
            "additionalProperties": False,
            "anyOf": [{"required": ["regex"]}, {"required": ["fields"]}],
            "properties": {
                "regex": _TEXT,
                "field": _TEXT,
                "fields": {
                    "type": "object",
                    "minProperties": 1,
                    "additionalProperties": {
                        "anyOf": [_SCALAR, {"type": "array", "items": _SCALAR, "minItems": 1}]
                    },
                },
            },
        },
        "extract": {"type": "array", "items": {"type": "string", "pattern": r"^[A-Za-z_]\w*$"}},
        "optional": {"type": "array", "items": {"type": "string", "pattern": r"^[A-Za-z_]\w*$"}},
        "examples": {"type": "array", "minItems": 1, "items": _EXAMPLE},
        "counter_examples": {"type": "array", "minItems": 1, "items": _COUNTER_EXAMPLE},
    },
}

_CARD: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["title", "kind"],
    "description": "top: most frequent values of `field`; count: how many entries; "
    "recent: the latest entries with `columns`. `when` picks the entries.",
    "properties": {
        "title": _TEXT,
        "kind": {"enum": ["top", "count", "recent"]},
        "field": _TEXT,
        "columns": _TEXT_LIST,
        "limit": {"type": "integer", "minimum": 1, "maximum": 50},
        "warn_at": {"type": "integer", "minimum": 1},
        "empty": _TEXT,
        "when": {
            "type": "object",
            "additionalProperties": False,
            "minProperties": 1,
            "properties": {
                "rules": _TEXT_LIST,
                "tags": _TEXT_LIST,
                "min_severity": {"enum": _SEVERITIES},
            },
        },
    },
    "if": {"properties": {"kind": {"const": "top"}}},
    "then": {"required": ["field"]},
}

OVERVIEW: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "applies_to": SELECTOR,
        "key_fields": {
            "type": "object",
            "minProperties": 1,
            "additionalProperties": _TEXT,
            "description": "field -> label named in the 'What is happening' paragraph",
        },
        "thresholds": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "error_rate": {"type": "number", "exclusiveMinimum": 0, "maximum": 1},
                "spike_z": {"type": "number", "exclusiveMinimum": 0},
                "spike_min_errors": {"type": "integer", "minimum": 1},
            },
        },
        "cards": {"type": "array", "minItems": 1, "items": _CARD},
    },
}

PACK: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["pack", "version", "example_source", "rules"],
    "properties": {
        "pack": {"type": "string", "pattern": r"^[a-z0-9_]+$"},
        "version": {"const": 1},
        "description": _TEXT,
        "applies_to": SELECTOR,
        "example_source": _TEXT,
        "overview": {"type": "object"},
        "rules": {"type": "array"},
    },
}
