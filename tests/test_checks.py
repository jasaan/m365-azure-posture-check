import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

import pytest

from posture.checks import (
    check_global_admin_count,
    check_legacy_auth_blocked,
    check_mfa_for_all,
    check_stale_guests,
    check_user_consent,
    run_all,
)
from posture.report import score
from posture.sources import FixtureSource

ROOT = Path(__file__).resolve().parent.parent
TODAY = dt.date(2026, 11, 20)


@pytest.fixture
def risky():
    return FixtureSource(ROOT / "fixtures" / "contoso-risky")


@pytest.fixture
def hardened():
    return FixtureSource(ROOT / "fixtures" / "contoso-hardened")


class FakeSource:
    """A source built from dicts, for edge cases the fixtures don't cover."""

    def __init__(self, **data):
        self.data = data

    def security_defaults(self):
        return self.data.get("security_defaults", {"isEnabled": False})

    def conditional_access_policies(self):
        return self.data.get("ca", [])

    def authorization_policy(self):
        return self.data.get("authz", {"defaultUserRolePermissions": {}})

    def user_registration_details(self):
        if "registration_error" in self.data:
            raise PermissionError(self.data["registration_error"])
        return self.data.get("registration", [])

    def global_admin_assignments(self):
        return self.data.get("ga", [])

    def guest_users(self):
        return self.data.get("guests", [])


def test_risky_tenant_fails_every_check(risky):
    results = {r.id: r.status for r in run_all(risky, today=TODAY)}
    assert results == {
        "MFA-ALL": "warn",
        "LEGACY-AUTH": "fail",
        "ADMIN-MFA": "fail",
        "GA-COUNT": "fail",
        "USER-CONSENT": "fail",
        "APP-REGISTRATION": "fail",
        "GUEST-INVITES": "fail",
        "STALE-GUESTS": "fail",
    }


def test_hardened_tenant_passes_every_check(hardened):
    results = run_all(hardened, today=TODAY)
    assert all(r.status == "pass" for r in results), [(r.id, r.status, r.evidence) for r in results]
    assert score(results) == 100


def test_risky_findings_name_the_accounts(risky):
    results = {r.id: r for r in run_all(risky, today=TODAY)}
    assert "helpdesk.lead@contoso.example" in results["ADMIN-MFA"].evidence
    assert "#EXT#" in results["GA-COUNT"].evidence
    assert "6 Global Administrators" in results["GA-COUNT"].evidence
    assert "674 days" in results["STALE-GUESTS"].evidence


def test_security_defaults_satisfy_mfa_and_legacy_auth():
    src = FakeSource(security_defaults={"isEnabled": True})
    assert check_mfa_for_all(src).status == "pass"
    assert check_legacy_auth_blocked(src).status == "pass"


def test_legacy_block_must_cover_both_client_types():
    policy = {
        "displayName": "Block EAS only",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"]},
            "clientAppTypes": ["exchangeActiveSync"],
        },
        "grantControls": {"builtInControls": ["block"]},
    }
    assert check_legacy_auth_blocked(FakeSource(ca=[policy])).status == "fail"


def test_single_global_admin_fails():
    ga = [{"principal": {"userPrincipalName": "only.admin@contoso.example"}}]
    assert check_global_admin_count(FakeSource(ga=ga)).status == "fail"


def test_low_impact_consent_is_a_warning():
    authz = {
        "defaultUserRolePermissions": {
            "permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-low"]
        }
    }
    assert check_user_consent(FakeSource(authz=authz)).status == "warn"


def test_missing_license_data_is_unknown_not_pass():
    guests = [
        {
            "userPrincipalName": "x#EXT#@contoso.onmicrosoft.com",
            "createdDateTime": "2020-01-01T00:00:00Z",
        }
    ]
    assert check_stale_guests(FakeSource(guests=guests), today=TODAY).status == "unknown"
    src = FakeSource(registration_error="403 Forbidden")
    results = {r.id: r.status for r in run_all(src, today=TODAY)}
    assert results["ADMIN-MFA"] == "unknown"


def test_cli_exit_code_and_outputs(tmp_path):
    cmd = [
        sys.executable,
        "-m",
        "posture",
        "--fixtures",
        str(ROOT / "fixtures" / "contoso-risky"),
        "--today",
        "2026-11-20",
        "--out",
        str(tmp_path),
    ]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    assert proc.returncode == 1  # critical/high failures gate a pipeline
    data = json.loads((tmp_path / "results.json").read_text())
    assert data["score"] < 20 and len(data["results"]) == 8
    ok = subprocess.run(
        [
            sys.executable,
            "-m",
            "posture",
            "--fixtures",
            str(ROOT / "fixtures" / "contoso-hardened"),
            "--today",
            "2026-11-20",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert ok.returncode == 0
