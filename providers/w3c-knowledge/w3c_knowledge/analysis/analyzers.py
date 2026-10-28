from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Classification:
    artifact_type: str
    primary_domain: str
    applicable_domains: list[str]
    confidence: float
    method: str
    evidence: list[str]


class KnowledgeAnalyzer(Protocol):
    version: str

    def classify(self, title: str, text: str) -> Classification:
        ...


class RuleBasedKnowledgeAnalyzer:
    version = "rule-based-0.1"

    def classify(self, title: str, text: str) -> Classification:
        haystack = f"{title}\n{text}".lower()
        if "privacy principles" in haystack:
            return Classification("principle", "privacy", ["privacy"], 0.95, self.version, ["title"])
        if "security and privacy questionnaire" in haystack:
            return Classification("questionnaire", "cross_cutting", ["privacy", "security"], 0.95, self.version, ["title"])
        if "ethical web principles" in haystack:
            return Classification(
                "principle",
                "cross_cutting",
                ["design", "privacy", "security", "accessibility", "internationalization", "ethics"],
                0.95,
                self.version,
                ["title"],
            )
        if "fingerprinting" in haystack:
            return Classification("topic_guidance", "privacy", ["privacy", "security"], 0.8, self.version, ["keyword"])
        if "accessibility" in haystack or "fast" in haystack:
            return Classification("topic_guidance", "accessibility", ["accessibility"], 0.75, self.version, ["keyword"])
        if "internationalization" in haystack or "i18n" in haystack:
            return Classification("topic_guidance", "internationalization", ["internationalization"], 0.75, self.version, ["keyword"])
        if "threat" in haystack or "security" in haystack:
            return Classification("topic_guidance", "security", ["security"], 0.7, self.version, ["keyword"])
        return Classification("operational_guidance", "cross_cutting", ["cross_cutting"], 0.5, self.version, ["fallback"])
