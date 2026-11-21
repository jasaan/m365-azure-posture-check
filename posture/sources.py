"""Where tenant data comes from.

Every check reads tenant settings through a Source with a handful of named methods.
FixtureSource reads recorded JSON files (used by the tests and the demo);
GraphSource calls Microsoft Graph with a signed-in admin's delegated, read-only access.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"  # built-in role template ID

# Microsoft Graph Command Line Tools: Microsoft's public client app for delegated Graph access.
GRAPH_CLI_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
READ_SCOPES = [
    "https://graph.microsoft.com/Policy.Read.All",
    "https://graph.microsoft.com/Directory.Read.All",
    "https://graph.microsoft.com/RoleManagement.Read.Directory",
    "https://graph.microsoft.com/AuditLog.Read.All",
    "https://graph.microsoft.com/Reports.Read.All",
]


class Source(Protocol):
    def security_defaults(self) -> dict: ...
    def conditional_access_policies(self) -> list[dict]: ...
    def authorization_policy(self) -> dict: ...
    def user_registration_details(self) -> list[dict]: ...
    def global_admin_assignments(self) -> list[dict]: ...
    def guest_users(self) -> list[dict]: ...


class FixtureSource:
    """Reads recorded Graph responses from a folder, one JSON file per method."""

    def __init__(self, folder: Path):
        self.folder = Path(folder)
        if not self.folder.is_dir():
            raise FileNotFoundError(f"No fixture folder at {self.folder}")

    def _load(self, name: str):
        data = json.loads((self.folder / f"{name}.json").read_text(encoding="utf-8"))
        return data["value"] if isinstance(data, dict) and "value" in data else data

    def security_defaults(self) -> dict:
        return self._load("security_defaults")

    def conditional_access_policies(self) -> list[dict]:
        return self._load("conditional_access_policies")

    def authorization_policy(self) -> dict:
        return self._load("authorization_policy")

    def user_registration_details(self) -> list[dict]:
        return self._load("user_registration_details")

    def global_admin_assignments(self) -> list[dict]:
        return self._load("global_admin_assignments")

    def guest_users(self) -> list[dict]:
        return self._load("guest_users")


class GraphSource:
    """Live, read-only Microsoft Graph calls with delegated sign-in.

    Needs an account that can read these settings (Global Reader is enough) and,
    for MFA registration and guest sign-in activity, Entra ID P1 or P2.
    """

    BASE = "https://graph.microsoft.com/v1.0"

    def __init__(self, tenant_id: str = "organizations"):
        import requests  # imported here so fixture mode needs no network libraries
        from azure.identity import InteractiveBrowserCredential

        self._requests = requests
        self._cred = InteractiveBrowserCredential(client_id=GRAPH_CLI_CLIENT_ID, tenant_id=tenant_id)
        self._token = None

    def _headers(self) -> dict:
        if self._token is None:
            self._token = self._cred.get_token(*READ_SCOPES).token
        return {
            "Authorization": f"Bearer {self._token}",
            "ConsistencyLevel": "eventual",
        }

    def _get(self, path: str, params: dict | None = None):
        resp = self._requests.get(f"{self.BASE}{path}", headers=self._headers(), params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _get_all(self, path: str, params: dict | None = None) -> list[dict]:
        data = self._get(path, params)
        items = list(data.get("value", []))
        while "@odata.nextLink" in data:
            resp = self._requests.get(data["@odata.nextLink"], headers=self._headers(), timeout=30)
            resp.raise_for_status()
            data = resp.json()
            items.extend(data.get("value", []))
        return items

    def security_defaults(self) -> dict:
        return self._get("/policies/identitySecurityDefaultsEnforcementPolicy")

    def conditional_access_policies(self) -> list[dict]:
        return self._get_all("/identity/conditionalAccess/policies")

    def authorization_policy(self) -> dict:
        return self._get("/policies/authorizationPolicy")

    def user_registration_details(self) -> list[dict]:
        return self._get_all("/reports/authenticationMethods/userRegistrationDetails")

    def global_admin_assignments(self) -> list[dict]:
        return self._get_all(
            "/roleManagement/directory/roleAssignments",
            {
                "$filter": f"roleDefinitionId eq '{GLOBAL_ADMIN_ROLE_ID}'",
                "$expand": "principal",
            },
        )

    def guest_users(self) -> list[dict]:
        return self._get_all(
            "/users",
            {
                "$filter": "userType eq 'Guest'",
                "$select": "id,displayName,userPrincipalName,createdDateTime,signInActivity",
                "$count": "true",
            },
        )
