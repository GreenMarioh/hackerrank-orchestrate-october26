"""Tests for RequestIntent classifier in code/ghost/intent.py."""

import pytest
from ghost.intent import (
    IntentClassifier,
    RequestIntent,
    normalize_text,
)


@pytest.fixture
def classifier() -> IntentClassifier:
    return IntentClassifier()


def test_normalize_text():
    assert normalize_text("  PLEASE\n\tDELETE   ") == "please delete"
    assert normalize_text("") == ""
    assert normalize_text(None) == ""


def test_standard_english_deletion_requests(classifier: IntentClassifier):
    requests = [
        "Please close my account and process the associated personal-data deletion.",
        "I would like the account associated with this address to be erased.",
        "I want to close this account and have its associated personal data deleted.",
        "Please process a permanent account-deletion request for this email address.",
        "I am asking you to remove my account and the personal information linked to it.",
        "I no longer use this account and would like it permanently deleted.",
        "Please purge all data related to my profile immediately.",
    ]
    for req in requests:
        res = classifier.classify(req)
        assert res.intent == RequestIntent.DELETION_AUTHORIZED, f"Failed on: {req}"


def test_multilingual_deletion_requests(classifier: IntentClassifier):
    # Portuguese
    pt = "Solicito a exclusão permanente da conta associada a este e-mail. Verifiquem os identificadores."
    assert classifier.classify(pt).intent == RequestIntent.DELETION_AUTHORIZED

    # Spanish
    es = "Solicito la eliminación permanente de la cuenta asociada a este correo. Revisen los identificadores."
    assert classifier.classify(es).intent == RequestIntent.DELETION_AUTHORIZED

    # French
    fr = "Je demande la suppression définitive du compte associé à cette adresse e-mail."
    assert classifier.classify(fr).intent == RequestIntent.DELETION_AUTHORIZED

    # Japanese
    ja = "このメールアドレスに関連するアカウントの完全な削除を依頼します。"
    assert classifier.classify(ja).intent == RequestIntent.DELETION_AUTHORIZED

    # Korean
    ko = "이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다."
    assert classifier.classify(ko).intent == RequestIntent.DELETION_AUTHORIZED

    # German
    de = "Bitte führen Sie die endgültige Löschung meines Benutzerkontos durch."
    assert classifier.classify(de).intent == RequestIntent.DELETION_AUTHORIZED

    # Italian
    it = "Chiedo la cancellazione definitiva del mio account e dei miei dati."
    assert classifier.classify(it).intent == RequestIntent.DELETION_AUTHORIZED


def test_non_deletion_requests_from_real_dataset_patterns(classifier: IntentClassifier):
    # From case_533 to case_542
    non_del = [
        "The mobile number on my profile is out of date. Please replace it with the new one and leave the account active.",
        "Please stop the promotional emails. I still need the account and my order history, so I am not asking for deletion.",
        "I'd like to download my account information in a portable format. Please keep the account as it is.",
        "I can't access my profile and need help resetting the login. Do not close the account.",
        "My surname is misspelled on the account. Can you correct it without removing any of my records?",
        "Please remove me from marketing lists only. I still want receipts and service messages for this account.",
        "Can you tell me what personal information you hold about me? This is an information request, not a request to erase it.",
        "I need a copy of last year's invoices for my records. Please leave my profile and purchase history in place.",
        "Please change the email address used for this account. I want to continue using the service.",
        "Could you send me a copy of the information held on my account? I still use it, so please don't delete or change anything.",
    ]
    for req in non_del:
        res = classifier.classify(req)
        assert res.intent == RequestIntent.NOT_APPLICABLE, f"Failed on non-deletion: {req} (got {res.intent}, reason={res.reason})"


def test_negation_and_mixed_intent(classifier: IntentClassifier):
    mixed_cases = [
        ("I want to export my data, do not delete my profile.", RequestIntent.NOT_APPLICABLE),
        ("Please don't delete my account, just update the shipping address.", RequestIntent.NOT_APPLICABLE),
        ("This is an access request under GDPR Art 15, not a request to erase my data.", RequestIntent.NOT_APPLICABLE),
        ("Unsubscribe from marketing emails only, keep the account active.", RequestIntent.NOT_APPLICABLE),
    ]
    for text, expected in mixed_cases:
        res = classifier.classify(text)
        assert res.intent == expected, f"Failed on: {text}"


def test_empty_and_ambiguous_requests(classifier: IntentClassifier):
    assert classifier.classify("").intent == RequestIntent.NOT_APPLICABLE
    assert classifier.classify("   ").intent == RequestIntent.NOT_APPLICABLE
    assert classifier.classify(None).intent == RequestIntent.NOT_APPLICABLE
    # Generic question without deletion intent
    assert classifier.classify("Hello, what are your opening hours?").intent == RequestIntent.NOT_APPLICABLE
