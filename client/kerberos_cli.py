"""Kerberos-style client utility commands for the demo.

This module wraps the existing AS/TGS/AP exchange functions with commands that
look closer to normal Kerberos user operations: kinit, klist, kvno, access,
renew, and kdestroy.
"""

from __future__ import annotations

import argparse
import getpass
import sys
import time

from client import client_app
from core.messages import APP_SERVICE_NAME, KDC_HOST, KDC_PORT
from core.principal import principal_realm, service_principal, user_principal


def _fmt_time(value) -> str:
    if not value:
        return "-"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(value)))
    except (TypeError, ValueError, OSError):
        return str(value)


def _cache_client_principal() -> str | None:
    metadata = client_app.cache.get_tgt_metadata()
    principal = metadata.get("client_principal")
    if principal:
        return str(principal)
    return None


def _require_cached_client() -> str | None:
    principal = _cache_client_principal()
    if not principal or not client_app.cache.has_tgt():
        print("No valid TGT in credential cache. Run kinit first.")
        return None
    client_app.client_principal_global = principal
    return principal


def _canonical_service(service_name: str, client_principal: str) -> str:
    if "@" in service_name:
        return service_principal(service_name)
    return service_principal(service_name, realm=principal_realm(client_principal))


def cmd_kinit(args: argparse.Namespace) -> int:
    principal = user_principal(args.principal)
    client_app.client_principal_global = principal
    password = args.password
    if password is None:
        password = getpass.getpass(f"Password for {principal}: ")
    if not password:
        print("Password cannot be empty.")
        return 1
    print(f"KDC: {KDC_HOST}:{KDC_PORT}")
    return 0 if client_app.phase1_as_exchange(principal, password) else 1


def cmd_klist(_args: argparse.Namespace) -> int:
    print(f"Credentials cache: {client_app.cache.path}")
    tgt, _session_key = client_app.cache.get_tgt()
    tgt_metadata = client_app.cache.get_tgt_metadata()
    service_tickets = client_app.cache.list_service_tickets()
    if tgt is None and not service_tickets:
        print("No credentials cache entries.")
        return 1

    if tgt is not None:
        print("\nTicket cache:")
        print(f"  client:     {tgt_metadata.get('client_principal', '-')}")
        print(f"  server:     {tgt_metadata.get('server_principal', '-')}")
        print(f"  starttime:  {_fmt_time(tgt_metadata.get('starttime'))}")
        print(f"  endtime:    {_fmt_time(tgt_metadata.get('endtime'))}")
        print(f"  renew_till: {_fmt_time(tgt_metadata.get('renew_till'))}")
        print(f"  kvno:       {tgt_metadata.get('ticket_kvno', '-')}")
        print(f"  enctype:    {tgt_metadata.get('enctype', tgt_metadata.get('ticket_enctype', '-'))}")

    if service_tickets:
        print("\nService tickets:")
        for principal, metadata in service_tickets:
            print(f"  {principal}")
            print(f"    endtime: {_fmt_time(metadata.get('endtime'))}")
            print(f"    kvno:    {metadata.get('ticket_kvno', '-')}")
            print(f"    enctype: {metadata.get('enctype', metadata.get('ticket_enctype', '-'))}")
    return 0


def cmd_kvno(args: argparse.Namespace) -> int:
    principal = _require_cached_client()
    if principal is None:
        return 1
    requested_service = _canonical_service(args.service, principal)
    if not client_app.phase2_tgs_exchange(args.service):
        return 1
    metadata = client_app.cache.get_service_ticket_metadata(requested_service)
    print(f"{requested_service}: kvno = {metadata.get('ticket_kvno', '-')}")
    return 0


def cmd_access(args: argparse.Namespace) -> int:
    principal = _require_cached_client()
    if principal is None:
        return 1
    requested_service = _canonical_service(args.service, principal)
    if not client_app.cache.has_service_ticket(requested_service):
        print(f"No cached service ticket for {requested_service}; requesting one first.")
        if not client_app.phase2_tgs_exchange(args.service):
            return 1
    return 0 if client_app.phase3_ap_exchange(args.service) else 1


def cmd_renew(_args: argparse.Namespace) -> int:
    principal = _require_cached_client()
    if principal is None:
        return 1
    client_app.client_principal_global = principal
    return 0 if client_app.renew_tgt_exchange() else 1


def cmd_kdestroy(_args: argparse.Namespace) -> int:
    path = client_app.cache.path
    client_app.cache.clear()
    print(f"Destroyed credential cache: {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m client.kerberos_cli",
        description="Kerberos-style client utility commands for this demo.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    kinit = subparsers.add_parser("kinit", help="Obtain and cache a TGT")
    kinit.add_argument("principal", help="Username or principal, e.g. alice")
    kinit.add_argument("--password", help="Demo convenience only; otherwise prompt securely")
    kinit.set_defaults(func=cmd_kinit)

    klist = subparsers.add_parser("klist", help="List credential cache entries")
    klist.set_defaults(func=cmd_klist)

    kvno = subparsers.add_parser("kvno", help="Obtain a service ticket and print its kvno")
    kvno.add_argument("service", nargs="?", default=APP_SERVICE_NAME)
    kvno.set_defaults(func=cmd_kvno)

    access = subparsers.add_parser("access", help="Access the application server using cached credentials")
    access.add_argument("service", nargs="?", default=APP_SERVICE_NAME)
    access.set_defaults(func=cmd_access)

    renew = subparsers.add_parser("renew", help="Renew the cached TGT")
    renew.set_defaults(func=cmd_renew)

    kdestroy = subparsers.add_parser("kdestroy", help="Destroy the credential cache")
    kdestroy.set_defaults(func=cmd_kdestroy)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
