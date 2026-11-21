# Microsoft 365 / Entra ID posture: contoso-risky (recorded sample data)

**Score: 9/100**  (0 of 8 checks passed)

| Status | Severity | Check | Evidence |
|---|---|---|---|
| WARN | critical | MFA required for all users | An all-users MFA policy exists but is report-only: MFA for all users (pilot). |
| FAIL | critical | Admins registered for MFA | 2 of 3 admins have no MFA method registered: helpdesk.lead@contoso.example, svc-backup-admin@contoso.example. |
| FAIL | high | Legacy authentication blocked | No enabled policy blocks Exchange ActiveSync and other legacy clients for all users. Legacy protocols can't do MFA, so password spray against them bypasses it. |
| FAIL | high | Global Administrators: 2 to 4, no guests | Guest account(s) hold Global Administrator: contractor_partner.example#EXT#@contoso.onmicrosoft.com. Also 6 Global Administrators in total (keep 2 to 4). |
| FAIL | high | User consent to apps restricted | Users can consent to any app for any permission (legacy default). This is the opening consent-phishing attacks use. |
| FAIL | medium | Regular users can't register applications | Any user can create app registrations, which can be used to persist access with app credentials. |
| FAIL | medium | Guest invitations restricted | Guest invitations can be sent by anyone, including guests (allowInvitesFrom = everyone). |
| FAIL | medium | No guest accounts inactive for 90+ days | 2 of 3 guests inactive 90+ days: rep_oldvendor.example#EXT#@contoso.onmicrosoft.com (674 days); temp_agency.example#EXT#@contoso.onmicrosoft.com (233 days). |

## Fixes, most severe first

### MFA required for all users (critical, WARN)

Create a Conditional Access policy for All users and All cloud apps that requires MFA (Entra admin center > Protection > Conditional Access), excluding only break-glass accounts. Or enable security defaults if you don't use Conditional Access.

References: CIS Microsoft 365 Foundations: Ensure MFA is enabled for all users; NIST CSF 2.0 PR.AA-03; ISO 27001:2022 8.5

### Admins registered for MFA (critical, FAIL)

Have each listed admin register a phishing-resistant method (FIDO2 key or Windows Hello) and require an authentication strength for admin roles in Conditional Access.

References: CIS Microsoft 365 Foundations: Ensure MFA is enabled for all users in administrative roles; NIST CSF 2.0 PR.AA-03; ISO 27001:2022 8.2, 8.5

### Legacy authentication blocked (high, FAIL)

Create a Conditional Access policy for All users with client apps 'Exchange ActiveSync' and 'Other clients' and grant control Block.

References: CIS Microsoft 365 Foundations: Ensure legacy authentication is blocked; NIST CSF 2.0 PR.AA-03; ISO 27001:2022 8.5

### Global Administrators: 2 to 4, no guests (high, FAIL)

Keep two to four Global Administrators (including break-glass), move everyone else to least-privileged roles, make remaining admin access eligible through PIM, and remove any guest from the role.

References: CIS Microsoft 365 Foundations: Ensure that between two and four global admins are designated; NIST CSF 2.0 PR.AA-05; ISO 27001:2022 8.2

### User consent to apps restricted (high, FAIL)

Set user consent to 'Do not allow' or 'Allow for apps from verified publishers, for selected permissions' (Enterprise applications > Consent and permissions) and turn on the admin consent workflow.

References: CIS Microsoft 365 Foundations: Ensure user consent to apps accessing company data is not allowed; NIST CSF 2.0 PR.AA-05; ISO 27001:2022 5.15

### Regular users can't register applications (medium, FAIL)

Set 'Users can register applications' to No (Entra admin center > Users > User settings) and grant the Application Developer role to people who need it.

References: CIS Microsoft 365 Foundations: Ensure third-party integrated applications are not allowed; NIST CSF 2.0 PR.AA-05; ISO 27001:2022 5.15

### Guest invitations restricted (medium, FAIL)

Limit guest invitations to admins and the Guest Inviter role (External Identities > External collaboration settings).

References: CIS Microsoft 365 Foundations: Ensure guest user invitations are limited to the Guest Inviter role; NIST CSF 2.0 PR.AA-05; ISO 27001:2022 5.18

### No guest accounts inactive for 90+ days (medium, FAIL)

Review the listed guests with their sponsors and remove those no longer needed; set up a recurring Access Review for guests.

References: CIS Microsoft 365 Foundations: Ensure guest access is reviewed regularly; NIST CSF 2.0 PR.AA-01; ISO 27001:2022 5.18


