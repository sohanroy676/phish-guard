# ADR-0003: Fixed URL feature set and rules

## Status
Accepted

## Date
2026-10-16

## Context
The roadmap says `features.py` comes from reference code that is not in the repo, and no feature list or rule schema was written down. Training and serving must share one definition.

## Decision
`core/url/features.py` defines `FEATURE_NAMES`, a fixed tuple of 30 features. `url_features()` always returns exactly those keys in that order as finite floats. Changing the tuple needs a new model version. `core/url/rules.py` returns `RuleHit(rule_id, severity, message)` items in a fixed order. All features and rules use only the URL string, the packaged word lists and tldextract's bundled suffix list.

## Alternatives considered
- Wait for the reference code: blocks v0.2.0.
- Dynamic feature set per input: breaks model input shape.

## Consequences
Models in v0.3.0 train on these 30 features. Word lists ship as package data and are the only tunable inputs.
