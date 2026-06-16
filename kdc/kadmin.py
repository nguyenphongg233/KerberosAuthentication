"""
kadmin.py - Command-line administrative utility for the Kerberos KDC database.

Supports:
- Adding/updating principals (add)
- Changing principal passwords (cpw)
- Deleting principals (delete)
- Listing all principals (list)
- Exporting service keys to keytabs (ktadd)
"""

import argparse
import os
import sqlite3
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from kdc.database import connect, upsert_principal, get_principal, resolve_principal, audit_event
from core.keytab import write_keytab
from core.messages import REALM


def cmd_add(args):
    conn = connect()
    try:
        cursor = conn.cursor()
        existing = get_principal(cursor, args.principal, resolve_alias=False)
        if existing:
            print(f"Error: Principal '{args.principal}' already exists.")
            return

        record = upsert_principal(conn, args.principal, args.password, args.type)
        conn.commit()
        print(f"Success: Principal '{record['principal_name']}' created successfully (type: {args.type}, kvno: 1).")
    finally:
        conn.close()


def cmd_cpw(args):
    conn = connect()
    try:
        cursor = conn.cursor()
        resolved = resolve_principal(cursor, args.principal)
        if not resolved:
            print(f"Error: Principal '{args.principal}' not found.")
            return

        existing = get_principal(cursor, resolved, resolve_alias=False)
        new_kvno = existing["kvno"] + 1

        record = upsert_principal(conn, resolved, args.password, existing["principal_type"], kvno=new_kvno)
        conn.commit()
        print(f"Success: Password changed for '{resolved}'. Key version bumped to kvno {new_kvno}.")
    finally:
        conn.close()


def cmd_delete(args):
    conn = connect()
    try:
        cursor = conn.cursor()
        resolved = resolve_principal(cursor, args.principal)
        if not resolved:
            print(f"Error: Principal '{args.principal}' not found.")
            return

        # We soft-delete by disabling, or hard delete? Standard is hard delete.
        conn.execute("DELETE FROM principals WHERE principal_name = ?", (resolved,))
        conn.execute("DELETE FROM principal_aliases WHERE principal_name = ?", (resolved,))
        audit_event(conn, "kadmin", "principal_deleted", resolved, "success")
        conn.commit()
        print(f"Success: Principal '{resolved}' deleted from KDC database.")
    finally:
        conn.close()


def cmd_list(args):
    conn = connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT principal_name, principal_type, kvno, enctype, disabled FROM principals")
        rows = cursor.fetchall()
        if not rows:
            print("No principals found in KDC database.")
            return

        print("\n" + "=" * 80)
        print(f"{'Principal Name':<45} | {'Type':<8} | {'kvno':<4} | {'Enctype':<24}")
        print("=" * 80)
        for row in rows:
            name, ptype, kvno, enctype, disabled = row
            status = " [DISABLED]" if disabled else ""
            print(f"{name + status:<45} | {ptype:<8} | {kvno:<4} | {enctype:<24}")
        print("=" * 80 + "\n")
    finally:
        conn.close()


def cmd_ktadd(args):
    conn = connect()
    try:
        cursor = conn.cursor()
        resolved = resolve_principal(cursor, args.principal)
        if not resolved:
            print(f"Error: Principal '{args.principal}' not found.")
            return

        record = get_principal(cursor, resolved, resolve_alias=False)
        if record["principal_type"] != "service":
            print(f"Warning: Principal '{resolved}' is type '{record['principal_type']}' (usually only services are exported to keytabs).")

        # Export keytab
        write_keytab(
            args.keytab,
            record["principal_name"],
            record["key"],
            record["kvno"],
            record["enctype"],
            record["realm"],
        )
        print(f"Success: Keys for '{record['principal_name']}' successfully exported to keytab: {args.keytab}")
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Kerberos KDC database administration utility.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # add
    p_add = subparsers.add_parser("add", help="Add a new principal.")
    p_add.add_argument("principal", help="Principal name (e.g. alice@DEMO.LOCAL or service/host@DEMO.LOCAL).")
    p_add.add_argument("-w", "--password", required=True, help="Plaintext password for key derivation.")
    p_add.add_argument("-t", "--type", choices=["user", "service", "tgs"], default="user", help="Principal type.")
    p_add.set_defaults(func=cmd_add)

    # cpw
    p_cpw = subparsers.add_parser("cpw", help="Change the password of a principal.")
    p_cpw.add_argument("principal", help="Principal name.")
    p_cpw.add_argument("-w", "--password", required=True, help="New plaintext password.")
    p_cpw.set_defaults(func=cmd_cpw)

    # delete
    p_del = subparsers.add_parser("delete", help="Delete a principal.")
    p_del.add_argument("principal", help="Principal name.")
    p_del.set_defaults(func=cmd_delete)

    # list
    p_list = subparsers.add_parser("list", help="List all principals.")
    p_list.set_defaults(func=cmd_list)

    # ktadd
    p_kt = subparsers.add_parser("ktadd", help="Export a service principal key to a keytab file.")
    p_kt.add_argument("principal", help="Service principal name.")
    p_kt.add_argument("-k", "--keytab", required=True, help="Destination keytab JSON path.")
    p_kt.set_defaults(func=cmd_ktadd)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
