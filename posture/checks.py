"""The posture checks. Each takes a Source and returns a Result.

Severity reflects how directly an attacker can use the gap. Status is one of
pass, fail, warn (partly configured or needs a human look) or unknown (data not
available, for example a license or permission is missing). Unknown is never a pass.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import asdict, dataclass, field

from .sources import Source


@dataclass
class Result:
    id: str
    title: str
    severity: str  # critical | high | medium | low
    status: str  # pass | fail | warn | unknown
    evidence: str
    fix: str
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _enabled(policy: dict) -> bool:
    return policy.get("state") == "enabled"


def _targets_all_users(policy: dict) -> bool:
    users = (policy.get("conditions") or {}).get("users") or {}
    return "All" in (users.get("includeUsers") or [])


def _grants(policy: dict, control: str) -> bool:
    grant = policy.get("grantControls") or {}
    return control in (grant.get("builtInControls") or [])


def _requires_mfa(policy: dict) -> bool:
    grant = policy.get("grantControls") or {}
    return _grants(policy, "mfa") or bool(grant.get("authenticationStrength"))


def check_mfa_for_all(src: Source) -> Result:
    base = dict(
        id="MFA-ALL",
        title="MFA required for all users",
        severity="critical",
        fix="Create a Conditional Access policy for All users and All cloud apps that requires MFA "
        "(Entra admin center > Protection > Conditional Access), excluding only break-glass accounts. "
        "Or enable security defaults if you don't use Conditional Access.",
        references=[
            "CIS Microsoft 365 Foundations: Ensure MFA is enabled for all users",
            "NIST CSF 2.0 PR.AA-03",
            "ISO 27001:2022 8.5",
        ],
    )
    if (src.security_defaults() or {}).get("isEnabled"):
        return Result(
            status="pass",
            evidence="Security defaults are enabled (MFA registration and challenges for all users).",
            **base,
        )
    hits = [
        p["displayName"]
        for p in src.conditional_access_policies()
        if _enabled(p) and _targets_all_users(p) and _requires_mfa(p)
    ]
    if hits:
        return Result(
            status="pass",
            evidence=f"Enabled Conditional Access policy requires MFA for all users: {', '.join(hits)}.",
            **base,
        )
    report_only = [
        p["displayName"]
        for p in src.conditional_access_policies()
        if p.get("state") == "enabledForReportingButNotEnforced" and _targets_all_users(p) and _requires_mfa(p)
    ]
    if report_only:
        return Result(
            status="warn",
            evidence=f"An all-users MFA policy exists but is report-only: {', '.join(report_only)}.",
            **base,
        )
    return Result(
        status="fail",
        evidence="Security defaults are off and no enabled Conditional Access policy requires MFA for all users.",
        **base,
    )


def check_legacy_auth_blocked(src: Source) -> Result:
    base = dict(
        id="LEGACY-AUTH",
        title="Legacy authentication blocked",
        severity="high",
        fix="Create a Conditional Access policy for All users with client apps 'Exchange ActiveSync' and "
        "'Other clients' and grant control Block.",
        references=[
            "CIS Microsoft 365 Foundations: Ensure legacy authentication is blocked",
            "NIST CSF 2.0 PR.AA-03",
            "ISO 27001:2022 8.5",
        ],
    )
    if (src.security_defaults() or {}).get("isEnabled"):
        return Result(
            status="pass",
            evidence="Security defaults are enabled, which block legacy authentication.",
            **base,
        )
    for p in src.conditional_access_policies():
        apps = set(((p.get("conditions") or {}).get("clientAppTypes")) or [])
        if _enabled(p) and _targets_all_users(p) and _grants(p, "block") and {"exchangeActiveSync", "other"} <= apps:
            return Result(
                status="pass",
                evidence=f"Blocked by Conditional Access policy '{p['displayName']}'.",
                **base,
            )
    return Result(
        status="fail",
        evidence="No enabled policy blocks Exchange ActiveSync and other legacy clients for all users. "
        "Legacy protocols can't do MFA, so password spray against them bypasses it.",
        **base,
    )


def check_admins_mfa_registered(src: Source) -> Result:
    base = dict(
        id="ADMIN-MFA",
        title="Admins registered for MFA",
        severity="critical",
        fix="Have each listed admin register a phishing-resistant method (FIDO2 key or Windows Hello) "
        "and require an authentication strength for admin roles in Conditional Access.",
        references=[
            "CIS Microsoft 365 Foundations: Ensure MFA is enabled for all users in administrative roles",
            "NIST CSF 2.0 PR.AA-03",
            "ISO 27001:2022 8.2, 8.5",
        ],
    )
    try:
        details = src.user_registration_details()
    except Exception as err:  # license or permission missing
        return Result(
            status="unknown",
            evidence=f"Registration report unavailable ({err}). It needs Entra ID P1/P2 and AuditLog.Read.All.",
            **base,
        )
    admins = [d for d in details if d.get("isAdmin")]
    missing = [d.get("userPrincipalName", "?") for d in admins if not d.get("isMfaRegistered")]
    if not admins:
        return Result(
            status="unknown",
            evidence="The report lists no admins; check that it covers privileged accounts.",
            **base,
        )
    if missing:
        return Result(
            status="fail",
            evidence=f"{len(missing)} of {len(admins)} admins have no MFA method registered: {', '.join(missing)}.",
            **base,
        )
    return Result(
        status="pass",
        evidence=f"Every admin ({len(admins)}) has an MFA method registered.",
        **base,
    )


def check_global_admin_count(src: Source) -> Result:
    base = dict(
        id="GA-COUNT",
        title="Global Administrators: 2 to 4, no guests",
        severity="high",
        fix="Keep two to four Global Administrators (including break-glass), "
        "move everyone else to least-privileged roles, "
        "make remaining admin access eligible through PIM, and remove any guest from the role.",
        references=[
            "CIS Microsoft 365 Foundations: Ensure that between two and four global admins are designated",
            "NIST CSF 2.0 PR.AA-05",
            "ISO 27001:2022 8.2",
        ],
    )
    assignments = src.global_admin_assignments()
    principals = [(a.get("principal") or {}) for a in assignments]
    names = [p.get("userPrincipalName") or p.get("displayName") or "?" for p in principals]
    guests = [n for n in names if "#EXT#" in n]
    count = len(assignments)
    if guests:
        extra = f" Also {count} Global Administrators in total (keep 2 to 4)." if count > 4 else ""
        return Result(
            status="fail",
            evidence=f"Guest account(s) hold Global Administrator: {', '.join(guests)}.{extra}",
            **base,
        )
    if count < 2:
        return Result(
            status="fail",
            evidence=f"Only {count} Global Administrator; a lockout or departure leaves no recovery path.",
            **base,
        )
    if count > 4:
        return Result(
            status="fail",
            evidence=f"{count} Global Administrators with active assignments: {', '.join(names)}.",
            **base,
        )
    return Result(
        status="pass",
        evidence=f"{count} Global Administrators: {', '.join(names)}.",
        **base,
    )


def check_user_consent(src: Source) -> Result:
    base = dict(
        id="USER-CONSENT",
        title="User consent to apps restricted",
        severity="high",
        fix="Set user consent to 'Do not allow' or 'Allow for apps from verified publishers, for selected permissions' "
        "(Enterprise applications > Consent and permissions) and turn on the admin consent workflow.",
        references=[
            "CIS Microsoft 365 Foundations: Ensure user consent to apps accessing company data is not allowed",
            "NIST CSF 2.0 PR.AA-05",
            "ISO 27001:2022 5.15",
        ],
    )
    perms = src.authorization_policy().get("defaultUserRolePermissions") or {}
    grants = perms.get("permissionGrantPoliciesAssigned") or []
    legacy = [g for g in grants if g.endswith("microsoft-user-default-legacy")]
    low = [g for g in grants if g.endswith("microsoft-user-default-low")]
    if legacy:
        return Result(
            status="fail",
            evidence="Users can consent to any app for any permission (legacy default). "
            "This is the opening consent-phishing attacks use.",
            **base,
        )
    if low:
        return Result(
            status="warn",
            evidence="Users can consent to verified-publisher apps for low-impact permissions. Acceptable if reviewed.",
            **base,
        )
    return Result(
        status="pass",
        evidence="Users can't grant consent to apps; an admin must approve.",
        **base,
    )


def check_users_can_register_apps(src: Source) -> Result:
    base = dict(
        id="APP-REGISTRATION",
        title="Regular users can't register applications",
        severity="medium",
        fix="Set 'Users can register applications' to No (Entra admin center > Users > User settings) "
        "and grant the Application Developer role to people who need it.",
        references=[
            "CIS Microsoft 365 Foundations: Ensure third-party integrated applications are not allowed",
            "NIST CSF 2.0 PR.AA-05",
            "ISO 27001:2022 5.15",
        ],
    )
    allowed = (src.authorization_policy().get("defaultUserRolePermissions") or {}).get("allowedToCreateApps")
    if allowed:
        return Result(
            status="fail",
            evidence="Any user can create app registrations, which can be used to persist access with app credentials.",
            **base,
        )
    return Result(
        status="pass",
        evidence="Only users with an admin or developer role can register apps.",
        **base,
    )


def check_guest_invites(src: Source) -> Result:
    base = dict(
        id="GUEST-INVITES",
        title="Guest invitations restricted",
        severity="medium",
        fix="Limit guest invitations to admins and the Guest Inviter role "
        "(External Identities > External collaboration settings).",
        references=[
            "CIS Microsoft 365 Foundations: Ensure guest user invitations are limited to the Guest Inviter role",
            "NIST CSF 2.0 PR.AA-05",
            "ISO 27001:2022 5.18",
        ],
    )
    who = src.authorization_policy().get("allowInvitesFrom")
    if who in ("everyone", "adminsGuestInvitersAndAllMembers"):
        label = "anyone, including guests" if who == "everyone" else "every member user"
        return Result(
            status="fail",
            evidence=f"Guest invitations can be sent by {label} (allowInvitesFrom = {who}).",
            **base,
        )
    return Result(
        status="pass",
        evidence=f"Guest invitations limited (allowInvitesFrom = {who}).",
        **base,
    )


def check_stale_guests(src: Source, today: dt.date | None = None, max_days: int = 90) -> Result:
    base = dict(
        id="STALE-GUESTS",
        title=f"No guest accounts inactive for {max_days}+ days",
        severity="medium",
        fix="Review the listed guests with their sponsors and remove those no longer needed; "
        "set up a recurring Access Review for guests.",
        references=[
            "CIS Microsoft 365 Foundations: Ensure guest access is reviewed regularly",
            "NIST CSF 2.0 PR.AA-01",
            "ISO 27001:2022 5.18",
        ],
    )
    today = today or dt.date.today()
    try:
        guests = src.guest_users()
    except Exception as err:
        return Result(status="unknown", evidence=f"Guest list unavailable ({err}).", **base)
    stale = []
    for g in guests:
        activity = g.get("signInActivity")
        if activity is None:
            return Result(
                status="unknown",
                evidence="Sign-in activity isn't available (it needs Entra ID P1/P2 and AuditLog.Read.All).",
                **base,
            )
        last = activity.get("lastSignInDateTime") or g.get("createdDateTime")
        last_date = dt.date.fromisoformat(last[:10])
        if (today - last_date).days >= max_days:
            stale.append(f"{g.get('userPrincipalName')} ({(today - last_date).days} days)")
    if stale:
        return Result(
            status="fail",
            evidence=f"{len(stale)} of {len(guests)} guests inactive {max_days}+ days: {'; '.join(stale)}.",
            **base,
        )
    return Result(
        status="pass",
        evidence=f"Every guest ({len(guests)}) signed in within {max_days} days.",
        **base,
    )


ALL_CHECKS = [
    check_mfa_for_all,
    check_legacy_auth_blocked,
    check_admins_mfa_registered,
    check_global_admin_count,
    check_user_consent,
    check_users_can_register_apps,
    check_guest_invites,
    check_stale_guests,
]


def run_all(src: Source, today: dt.date | None = None) -> list[Result]:
    results = []
    for check in ALL_CHECKS:
        results.append(check(src, today=today) if check is check_stale_guests else check(src))
    return results
