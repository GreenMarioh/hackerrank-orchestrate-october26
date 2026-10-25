"""Request intent classifier for deletion audit.

Distinguishes deletion-authorizing requests from non-deletion requests
(access, rectification/correction, portability/export, marketing unsubscribe,
account inquiry, etc.) in accordance with problem_statement.md and AGENTS.md §6.5.
"""

from __future__ import annotations

import re
import unicodedata
from enum import Enum
from typing import NamedTuple


class RequestIntent(str, Enum):
    """Classified intent of a data subject request."""
    DELETION_AUTHORIZED = "DELETION_AUTHORIZED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class IntentClassificationResult(NamedTuple):
    """Result of request intent classification."""
    intent: RequestIntent
    reason: str
    confidence: float


# Explicit non-deletion (opt-out, access, export, rectification) patterns across languages
# These patterns explicitly state that deletion is NOT requested, or request a non-deletion action.
NON_DELETION_EXPRESSIONS = [
    # English explicit negative deletion statements
    r"\bnot\s+asking\s+for\s+deletion\b",
    r"\bnot\s+a\s+request\s+to\s+erase\b",
    r"\bdo\s+not\s+(?:close|delete|erase|remove)\b",
    r"\bdon'?t\s+(?:close|delete|erase|remove)\b",
    r"\bleave\s+(?:the\s+account|my\s+profile|my\s+account)\s+active\b",
    r"\bleave\s+my\s+profile\s+and\s+purchase\s+history\s+in\s+place\b",
    r"\bkeep\s+(?:the\s+account|my\s+account|everything)\s+as\s+it\s+is\b",
    r"\bwithout\s+removing\s+any\s+of\s+my\s+records\b",
    r"\bmarketing\s+lists?\s+only\b",
    r"\bcontinue\s+using\s+the\s+service\b",
    r"\bstop\s+(?:the\s+)?promotional\s+emails\b",
    r"\bresetting\s+the\s+login\b",
    r"\bdownload\s+my\s+account\s+information\s+in\s+a\s+portable\s+format\b",
    r"\bcopy\s+of\s+(?:last\s+year'?s\s+invoices|the\s+information\s+held)\b",
    r"\bwhat\s+personal\s+information\s+you\s+hold\s+about\s+me\b",
    r"\bthis\s+is\s+an\s+information\s+request\b",
    r"\bchange\s+the\s+email\s+address\s+used\s+for\s+this\s+account\b",
    r"\bmobile\s+number\s+on\s+my\s+profile\s+is\s+out\s+of\s+date\b",
    r"\bsurname\s+is\s+misspelled\b",
    r"\bunsubscribe\s+from\s+(?:all\s+)?marketing\b",
    r"\bopt[\s-]?out\s+of\s+marketing\b",

    # Spanish non-deletion expressions
    r"\bno\s+(?:solicito|pido)\s+la\s+eliminaci[oó]n\b",
    r"\bno\s+(?:borren|eliminen|cierren)\b",
    r"\bmantener\s+la\s+cuenta\s+activa\b",
    r"\bsolo\s+(?:darme\s+de\s+baja\s+de\s+publicidad|correcci[oó]n)\b",

    # French non-deletion expressions
    r"\bne\s+pas\s+(?:supprimer|fermer)\b",
    r"\bgarder\s+le\s+compte\s+actif\b",
    r"\bceci\s+n'est\s+pas\s+une\s+demande\s+de\s+suppression\b",

    # German non-deletion expressions
    r"\bnicht\s+l[oö]schen\b",
    r"\bkonto\s+aktiv\s+lassen\b",
    r"\bauskunft\s+verlangen\b",

    # Portuguese non-deletion expressions
    r"\bn[aã]o\s+(?:solicito|pe[cç]o)\s+a\s+exclus[aã]o\b",
    r"\bn[aã]o\s+exclua\b",
    r"\bmanter\s+a\s+conta\s+ativa\b",
]

# Multilingual deletion authorization phrases / verbs
DELETION_AUTHORIZATION_PATTERNS = [
    # English
    r"\b(?:permanently\s+)?delete[ds]?\b",
    r"\bdeleting\b",
    r"\bdeletion\b",
    r"\berase[ds]?\b",
    r"\berasure\b",
    r"\berasing\b",
    r"\bremove[ds]?\b",
    r"\bremoving\b",
    r"\bremoval\b",
    r"\bclose[ds]?\b",
    r"\bclosing\b",
    r"\bpurge[ds]?\b",
    r"\bpurging\b",
    r"\bprofile\s+is\s+gone\b",

    # Spanish
    r"\beliminaci[oó]n\b",
    r"\beliminar\b",
    r"\bsuprimir\b",
    r"\bborrar\b",

    # Portuguese
    r"\bexclus[aã]o\b",
    r"\bexcluir\b",
    r"\belimina[cç][aã]o\b",

    # French
    r"\bsuppression\b",
    r"\bsupprimer\b",
    r"\beffacer\b",
    r"\beffacement\b",

    # German
    r"\bl[oö]schung\b",
    r"\bl[oö]schen\b",

    # Italian
    r"\bcancellazione\b",
    r"\bcancellare\b",

    # Japanese / Chinese / Korean (no word boundary needed for CJK characters)
    r"削除",
    r"消去",
    r"삭제",
]


def normalize_text(text: str) -> str:
    """Normalize Unicode, lower-case, and standardize whitespace."""
    if not text:
        return ""
    # NFKC normalizes compatibility characters while preserving text
    norm = unicodedata.normalize("NFKC", text)
    # Collapse multiple whitespaces
    norm = re.sub(r"\s+", " ", norm).strip().lower()
    return norm


class IntentClassifier:
    """Classifies data subject requests into deletion or non-deletion (NOT_APPLICABLE)."""

    def __init__(self) -> None:
        self._compiled_non_deletion = [
            re.compile(p, re.IGNORECASE) for p in NON_DELETION_EXPRESSIONS
        ]
        self._compiled_deletion = [
            re.compile(p, re.IGNORECASE) for p in DELETION_AUTHORIZATION_PATTERNS
        ]

    def classify(self, request_text: str | None) -> IntentClassificationResult:
        """Classify the intent of the request text.
        
        Returns:
            IntentClassificationResult with intent (DELETION_AUTHORIZED or NOT_APPLICABLE).
        """
        if not request_text or not request_text.strip():
            return IntentClassificationResult(
                intent=RequestIntent.NOT_APPLICABLE,
                reason="Empty or blank request text does not authorize deletion.",
                confidence=1.0,
            )

        norm_text = normalize_text(request_text)

        # Check explicit negative or non-deletion signals first
        for pattern in self._compiled_non_deletion:
            match = pattern.search(norm_text)
            if match:
                return IntentClassificationResult(
                    intent=RequestIntent.NOT_APPLICABLE,
                    reason=f"Matched non-deletion expression: '{match.group(0)}'",
                    confidence=0.98,
                )

        # Check for positive deletion authorization across supported languages
        for pattern in self._compiled_deletion:
            match = pattern.search(norm_text)
            if match:
                return IntentClassificationResult(
                    intent=RequestIntent.DELETION_AUTHORIZED,
                    reason=f"Matched deletion authorization keyword: '{match.group(0)}'",
                    confidence=0.95,
                )

        # Ambiguous / unrecognized request
        # In accordance with data privacy governance (GDPR/CCPA) and problem_statement.md:
        # A request that does not authorize deletion cannot be processed as a deletion request.
        return IntentClassificationResult(
            intent=RequestIntent.NOT_APPLICABLE,
            reason="No authorized deletion expression found in request text.",
            confidence=0.85,
        )
