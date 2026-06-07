"""Principal and realm helpers for the Kerberos demo."""

from __future__ import annotations

import os


DEFAULT_REALM = os.getenv("KRB_REALM", "DEMO.LOCAL").upper()
DEFAULT_SERVICE_HOST = os.getenv("APP_SERVER_NAME", "localhost").lower()


def user_principal(username_or_principal: str, realm: str = DEFAULT_REALM) -> str:
    """Return a canonical user principal, e.g. alice@DEMO.LOCAL."""
    value = username_or_principal.strip()
    if "@" in value:
        name, existing_realm = value.rsplit("@", 1)
        return f"{name}@{existing_realm.upper()}"
    return f"{value}@{realm.upper()}"


def service_principal(service_or_principal: str, host: str = DEFAULT_SERVICE_HOST,
                      realm: str = DEFAULT_REALM) -> str:
    """Return a canonical service principal, e.g. fileserver/localhost@DEMO.LOCAL."""
    value = service_or_principal.strip()
    if "@" in value and "/" in value.split("@", 1)[0]:
        name, existing_realm = value.rsplit("@", 1)
        service, existing_host = name.split("/", 1)
        return f"{service.lower()}/{existing_host.lower()}@{existing_realm.upper()}"
    if "/" in value:
        service, existing_host = value.split("/", 1)
        return f"{service.lower()}/{existing_host.lower()}@{realm.upper()}"
    return f"{value.lower()}/{host.lower()}@{realm.upper()}"


def tgs_principal(realm: str = DEFAULT_REALM) -> str:
    """Return the TGS principal for a realm."""
    normalized_realm = realm.upper()
    return f"krbtgt/{normalized_realm}@{normalized_realm}"


def principal_realm(principal: str, default: str = DEFAULT_REALM) -> str:
    """Extract the realm from a principal."""
    if "@" not in principal:
        return default.upper()
    return principal.rsplit("@", 1)[1].upper()


def principal_salt(principal: str, realm: str | None = None) -> str:
    """
    Return a deterministic per-principal salt.

    Real Kerberos string-to-key salts are enctype-specific. This demo uses a
    clear deterministic salt so the client can derive the same key as the KDC
    before contacting the AS.
    """
    normalized_realm = (realm or principal_realm(principal)).upper()
    return f"{normalized_realm}:{principal}"


def principal_aliases(principal: str) -> list[str]:
    """Return convenient short aliases for a canonical principal."""
    local = principal.split("@", 1)[0]
    aliases = [local]
    if "/" in local:
        aliases.append(local.split("/", 1)[0])
    return list(dict.fromkeys(aliases))
