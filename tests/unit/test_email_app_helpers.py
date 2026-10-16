import pytest

from phishguard.app.security import UNKNOWN_SENDER, defang_sender, email_hmac
from phishguard.core.email.parse import from_fields
from phishguard.core.email.scoring import load_email_scorer
from phishguard.core.explain import EMAIL_REASON, lr_reasons
from phishguard.core.registry import ModelIntegrityError
from phishguard.core.risk import CANT_ASSESS, HIGH, LOW, SUSPICIOUS, combine_email, higher
from phishguard.core.url.rules import RuleHit

HIGH_RULE = RuleHit("x", "high", "m")
WARN_RULE = RuleHit("y", "warn", "m")


def test_higher_orders_cant_assess_between_low_and_suspicious():
    assert higher(LOW, CANT_ASSESS) == CANT_ASSESS
    assert higher(CANT_ASSESS, SUSPICIOUS) == SUSPICIOUS
    assert higher(SUSPICIOUS, HIGH, LOW) == HIGH


def test_combine_email_takes_worst_link_and_rules_only_raise():
    assert combine_email(LOW, [], []) == LOW
    assert combine_email(LOW, [HIGH], []) == HIGH
    assert combine_email(HIGH, [LOW], [WARN_RULE]) == HIGH
    assert combine_email(LOW, [], [HIGH_RULE]) == SUSPICIOUS
    assert combine_email(LOW, [CANT_ASSESS], [HIGH_RULE]) == SUSPICIOUS
    assert combine_email(LOW, [CANT_ASSESS], [WARN_RULE]) == CANT_ASSESS


@pytest.mark.parametrize(
    ("sender", "expected"),
    [
        ("Alice <alice@Mail.Example.com>", "mail[.]example[.]com"),
        ("alice@example.com", "example[.]com"),
        ("no address here", UNKNOWN_SENDER),
        ("", UNKNOWN_SENDER),
        ("a@<script>.com", UNKNOWN_SENDER),
    ],
)
def test_defang_sender_keeps_only_the_domain(sender, expected):
    assert defang_sender(from_fields("s", sender, "b")) == expected


def test_email_hmac_is_keyed_and_content_sensitive():
    a, b = from_fields("s", "a@b.com", "body"), from_fields("s", "a@b.com", "body2")
    assert email_hmac("p" * 20, a) == email_hmac("p" * 20, a)
    assert email_hmac("p" * 20, a) != email_hmac("p" * 20, b)
    assert email_hmac("q" * 20, a) != email_hmac("p" * 20, a)
    assert "body" not in email_hmac("p" * 20, a)


def test_load_email_scorer_scores_in_unit_range(email_models_root):
    scorer = load_email_scorer("v1", email_models_root)
    phish = scorer.score(from_fields("Urgent", "", "verify your account password now urgent"))
    ham = scorer.score(from_fields("Notes", "", "meeting agenda notes lunch project"))
    assert 0 <= ham < phish <= 1


def test_load_email_scorer_rejects_non_text_primary(email_models_root):
    import json

    path = email_models_root / "email" / "v1" / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["models"]["lr_text"]["input"] = "features"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ModelIntegrityError):
        load_email_scorer("v1", email_models_root)


def test_lr_reasons_uses_the_email_template(email_models_root):
    scorer = load_email_scorer("v1", email_models_root)
    text = scorer.text(from_fields("Urgent", "", "verify your account password now urgent"))
    reasons = lr_reasons(scorer.model, text, template=EMAIL_REASON)
    assert reasons and all(r.startswith("The email text contains") for r in reasons)
