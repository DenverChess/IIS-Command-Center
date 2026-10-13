"""IIS Sentinel admin CLI.

    python sentinelctl.py set-admin-password [--user NAME] [--from-env VAR]
    python sentinelctl.py show-admin
    python sentinelctl.py run

`--from-env` reads the password from an environment variable (used by the installer so the password never appears
on a command line); otherwise it is prompted for twice.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys

MIN_LENGTH = 8


def _set_admin_password(args: argparse.Namespace) -> int:
    import local_admin

    if args.from_env:
        password = os.environ.pop(args.from_env, "")
        if not password:
            print(f"error: environment variable {args.from_env} is empty", file=sys.stderr)
            return 2
    else:
        password = getpass.getpass("New break-glass password: ")
        if getpass.getpass("Confirm password: ") != password:
            print("error: passwords do not match", file=sys.stderr)
            return 2
    if len(password) < MIN_LENGTH:
        print(f"error: password must be at least {MIN_LENGTH} characters", file=sys.stderr)
        return 2
    user = (args.user or "").strip() or (local_admin.load() or {}).get("user") or local_admin.DEFAULT_USER
    local_admin.save(user, password)
    print(f"Break-glass account '{user}' saved to {local_admin.CRED_FILE}")
    return 0


def _show_admin(_args: argparse.Namespace) -> int:
    import local_admin

    cred = local_admin.load()
    print(f"Break-glass account: {cred['user']}" if cred else "No break-glass account configured")
    return 0 if cred else 1


def _run(_args: argparse.Namespace) -> int:
    import runpy

    sys.argv = ["main.py"]
    runpy.run_path(os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py"), run_name="__main__")
    return 0


def main(argv: list[str] | None = None) -> int:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    parser = argparse.ArgumentParser(prog="sentinelctl", description="IIS Sentinel admin tool")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("set-admin-password", help="Create or reset the break-glass local admin")
    p.add_argument("--user", help="Account name (default: keep existing, or sentinel-admin)")
    p.add_argument("--from-env", metavar="VAR", help="Read the password from this environment variable")
    p.set_defaults(fn=_set_admin_password)
    sub.add_parser("show-admin", help="Show the configured break-glass account").set_defaults(fn=_show_admin)
    sub.add_parser("run", help="Run the server in the foreground").set_defaults(fn=_run)
    args = parser.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
