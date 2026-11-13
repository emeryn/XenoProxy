"""Two-factor authentication, TLP policy and instance settings."""

from __future__ import annotations

import time

import pyotp
import pytest

from app.core.errors import ValidationFailedError
from app.models.job import Tlp
from app.models.user import AuthSource, Role, User
from app.services import mfa
from app.services import tlp as tlp_policy
from app.services.settings_store import BY_KEY, SPECS, SettingSpec, _coerce


def make_user(**overrides: object) -> User:
    defaults: dict[str, object] = {
        "username": "analyst",
        "role": Role.ANALYST,
        "auth_source": AuthSource.LOCAL,
        "is_active": True,
        "mfa_enabled": False,
        "mfa_secret_key_version": 1,
    }
    defaults.update(overrides)
    return User(**defaults)  # type: ignore[arg-type]


# --- TOTP -------------------------------------------------------------------


def test_enrolment_produces_a_scannable_uri() -> None:
    user = make_user()
    enrolment = mfa.generate_enrolment(user)
    assert enrolment.otpauth_uri.startswith("otpauth://totp/XenoProxy%3Aanalyst?")
    assert f"secret={enrolment.secret}" in enrolment.otpauth_uri
    assert "issuer=XenoProxy" in enrolment.otpauth_uri
    assert "period=30" in enrolment.otpauth_uri


def test_the_secret_is_sealed_not_stored_in_clear() -> None:
    user = make_user()
    enrolment = mfa.generate_enrolment(user)
    mfa.store_secret(user, enrolment.secret)

    assert user.mfa_secret_ciphertext
    assert enrolment.secret not in (user.mfa_secret_ciphertext or "")
    assert enrolment.secret not in (user.mfa_secret_wrapped_key or "")
    assert mfa.read_secret(user) == enrolment.secret


def test_a_valid_code_is_accepted() -> None:
    user = make_user()
    enrolment = mfa.generate_enrolment(user)
    mfa.store_secret(user, enrolment.secret)
    code = pyotp.TOTP(enrolment.secret).now()
    assert mfa.verify_code(user, code) is True


def test_the_same_code_cannot_be_replayed() -> None:
    user = make_user()
    enrolment = mfa.generate_enrolment(user)
    mfa.store_secret(user, enrolment.secret)
    code = pyotp.TOTP(enrolment.secret).now()

    assert mfa.verify_code(user, code) is True
    assert mfa.verify_code(user, code) is False


def test_a_code_from_an_earlier_step_is_refused() -> None:
    """Prevents a captured code from being used after a newer one was accepted."""
    user = make_user()
    enrolment = mfa.generate_enrolment(user)
    mfa.store_secret(user, enrolment.secret)
    totp = pyotp.TOTP(enrolment.secret)
    now = time.time()

    assert mfa.verify_code(user, totp.at(now), at=now) is True
    older = now - mfa.TIME_STEP_SECONDS
    assert mfa.verify_code(user, totp.at(older), at=now) is False


def test_a_wrong_code_is_refused() -> None:
    user = make_user()
    enrolment = mfa.generate_enrolment(user)
    mfa.store_secret(user, enrolment.secret)
    assert mfa.verify_code(user, "000000") is False
    assert mfa.verify_code(user, "not-a-code") is False


def test_a_code_without_a_secret_is_refused() -> None:
    assert mfa.verify_code(make_user(), "123456") is False


def test_clearing_removes_every_trace_of_the_secret() -> None:
    user = make_user()
    enrolment = mfa.generate_enrolment(user)
    mfa.store_secret(user, enrolment.secret)
    user.mfa_enabled = True

    mfa.clear_secret(user)
    assert user.mfa_enabled is False
    assert user.mfa_secret_ciphertext is None
    assert mfa.read_secret(user) is None


# --- TLP --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("job_tlp", "analyzer_max", "expected"),
    [
        (Tlp.CLEAR, Tlp.CLEAR, True),
        (Tlp.CLEAR, Tlp.RED, True),
        (Tlp.GREEN, Tlp.CLEAR, False),
        (Tlp.GREEN, Tlp.AMBER, True),
        (Tlp.AMBER, Tlp.AMBER, True),
        (Tlp.AMBER, Tlp.GREEN, False),
        (Tlp.RED, Tlp.AMBER, False),
        (Tlp.RED, Tlp.RED, True),
    ],
)
def test_tlp_gates_which_analyzers_may_run(job_tlp: Tlp, analyzer_max: Tlp, expected: bool) -> None:
    assert tlp_policy.allows(job_tlp, analyzer_max) is expected


def test_red_excludes_every_source_that_leaves_the_deployment() -> None:
    from app.plugins import load_all
    from app.plugins.base.registry import iter_analyzers

    load_all()
    allowed = [cls.name for cls in iter_analyzers() if tlp_policy.allows(Tlp.RED, cls.max_tlp)]
    assert "dns" in allowed
    assert "shodan" not in allowed
    assert "virustotal" not in allowed
    assert "urlscan" not in allowed


def test_clear_allows_the_sources_that_publish_the_observable() -> None:
    from app.plugins import load_all
    from app.plugins.base.registry import iter_analyzers

    load_all()
    allowed = [cls.name for cls in iter_analyzers() if tlp_policy.allows(Tlp.CLEAR, cls.max_tlp)]
    assert "urlscan" in allowed
    assert "joesandbox_cloud" in allowed


def test_a_self_hosted_sandbox_is_allowed_above_what_a_public_one_is() -> None:
    """The deployment, not the vendor, decides how far an observable may go."""
    from app.plugins import load_all
    from app.plugins.base.registry import get_plugin

    load_all()
    # Cloud Basic publishes every submission, so TLP:CLEAR is its ceiling.
    assert tlp_policy.allows(Tlp.AMBER, get_plugin("joesandbox_cloud").max_tlp) is False
    # An appliance keeps the sample inside, so AMBER and RED are fine.
    assert tlp_policy.allows(Tlp.RED, get_plugin("joesandbox_enterprise").max_tlp) is True


def test_amber_and_above_restrict_visibility() -> None:
    assert tlp_policy.restricts_visibility(Tlp.AMBER) is True
    assert tlp_policy.restricts_visibility(Tlp.RED) is True
    assert tlp_policy.restricts_visibility(Tlp.GREEN) is False
    assert tlp_policy.restricts_visibility(Tlp.CLEAR) is False


# --- settings ---------------------------------------------------------------


def test_every_setting_declares_a_usable_specification() -> None:
    for spec in SPECS:
        assert spec.key and spec.label and spec.help_text
        assert spec.section in {"security", "scanning", "retention"}
        if spec.type == "choice":
            assert spec.choices and spec.default in spec.choices
        if spec.type == "integer":
            assert isinstance(spec.default, int)
            assert spec.minimum is not None and spec.maximum is not None


def test_setting_keys_are_unique() -> None:
    assert len(BY_KEY) == len(SPECS)


def test_an_out_of_range_integer_is_refused() -> None:
    spec = BY_KEY["session_idle_minutes"]
    with pytest.raises(ValidationFailedError):
        _coerce(spec, 1)
    with pytest.raises(ValidationFailedError):
        _coerce(spec, 100000)
    assert _coerce(spec, 30) == 30


def test_a_wrong_type_is_refused() -> None:
    with pytest.raises(ValidationFailedError):
        _coerce(BY_KEY["require_mfa_for_all"], "yes")
    with pytest.raises(ValidationFailedError):
        _coerce(BY_KEY["session_idle_minutes"], True)


def test_a_value_outside_the_choices_is_refused() -> None:
    with pytest.raises(ValidationFailedError):
        _coerce(BY_KEY["default_tlp"], "purple")
    assert _coerce(BY_KEY["default_tlp"], "red") == "red"


def test_a_string_setting_is_bounded() -> None:
    spec = SettingSpec(
        key="demo", label="Demo", help_text="", type="string", default="", section="security"
    )
    with pytest.raises(ValidationFailedError):
        _coerce(spec, "x" * 600)
