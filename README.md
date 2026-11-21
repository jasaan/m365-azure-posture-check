# m365-azure-posture-check

**A read-only Python tool that checks a Microsoft 365 / Entra ID tenant for the settings attackers exploit most: missing MFA, legacy authentication, too many Global Admins, open app consent, and stale guests. It gives each check pass/fail/warn with the accounts and policies involved, a weighted score, and the fix.**

> Built with Claude; designed, reviewed and tested by me. Tests run against recorded sample data for two fictional tenants. The live mode (`--live`) uses Microsoft Graph's documented read endpoints but **hasn't been run against a real tenant yet**; please report anything that doesn't work.

## Checks

| ID | Check | Severity | Fails when |
|---|---|---|---|
| MFA-ALL | MFA required for all users | Critical | Security defaults are off and no enabled Conditional Access policy requires MFA (or an authentication strength) for All users. Report-only policies count as a warning. |
| ADMIN-MFA | Admins registered for MFA | Critical | Any admin has no MFA method registered. |
| LEGACY-AUTH | Legacy authentication blocked | High | No enabled policy blocks both Exchange ActiveSync and other legacy clients for All users. |
| GA-COUNT | Global Administrators: 2 to 4, no guests | High | Fewer than 2 or more than 4 active Global Admins, or any guest in the role. |
| USER-CONSENT | User consent to apps restricted | High | Users can consent to any app (the legacy default). Verified-publisher, low-impact consent is a warning. |
| APP-REGISTRATION | Regular users can't register apps | Medium | Any user can create app registrations. |
| GUEST-INVITES | Guest invitations restricted | Medium | Anyone (or every member) can invite guests. |
| STALE-GUESTS | No guests inactive 90+ days | Medium | A guest hasn't signed in (or never signed in) for 90 days. |

Each result includes the evidence (named accounts and policies), the fix with the admin-center path, and references to the CIS Microsoft 365 Foundations Benchmark, NIST CSF 2.0 and ISO 27001. When data isn't available (missing license or permission), the result is **unknown, never pass**.

The score weights checks by severity (critical 4, high 3, medium 2); a warning counts half. The command exits with code 1 when any critical or high check fails, so it can gate a pipeline or a scheduled job.

## Try it (no sign-in needed)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

python -m posture --fixtures fixtures/contoso-risky --today 2026-11-20
python -m posture --fixtures fixtures/contoso-hardened --today 2026-11-20
pytest -q
```

The risky tenant scores **9/100** with every check failing or warning; the hardened tenant scores **100/100**. See the full output in [`examples/contoso-risky-report.md`](examples/contoso-risky-report.md). The fixtures are real Microsoft Graph response shapes with fictional data.

## Run it against your tenant

```bash
python -m posture --live --tenant yourtenant.onmicrosoft.com --out out/
```

- **Read-only.** It only calls `GET` endpoints with delegated read scopes: `Policy.Read.All`, `Directory.Read.All`, `RoleManagement.Read.Directory`, `AuditLog.Read.All`, `Reports.Read.All`.
- **Sign-in** opens a browser using Microsoft's public "Microsoft Graph Command Line Tools" app. An account with the **Global Reader** role is enough. Your tenant may require admin consent for these scopes the first time.
- **Licensing:** the MFA registration report and guest sign-in activity need Entra ID P1 or P2. Without them those checks return unknown.
- **Use a tenant you own or are authorized to assess.** Microsoft's free developer program tenant is a good place to try it.

## How it's built

```
posture/sources.py   FixtureSource (recorded JSON) and GraphSource (live Microsoft Graph), same interface
posture/checks.py    one function per check -> Result(status, severity, evidence, fix, references)
posture/report.py    weighted score, Markdown report, JSON results
posture/__main__.py  command line
tests/               9 tests: both sample tenants, edge cases, exit codes
```

Adding a check means writing one function that reads from the source and returns a `Result`, plus a test.

## Design choices

- **Evidence over verdicts.** Every failure names the accounts or policies involved, so the person fixing it doesn't have to go hunting.
- **Unknown isn't pass.** Missing data is reported as unknown so a license gap can't hide a risk.
- **Testable without a tenant.** The same checks run against recorded responses, so behavior is pinned down by tests and CI.
- **Read-only by design.** The tool never changes settings; fixes are written for a person to apply through change management.

## License

MIT
