#!/usr/bin/env python3
"""Guard (§4.5): no script or realm file of this repo may set the realm user profile
unmanagedAttributePolicy to ENABLED. ENABLED lets users self-edit unmanaged attributes through the account
console / account REST API, i.e. the tenant binding attributes tenant_id and continuum_user_id that end up
as token claims. Allowed values: ADMIN_EDIT (admin read/write only) or ADMIN_VIEW.

Exit 1 (and list the offending lines) when a violation is found. Called at the top of the recette scripts so
that running any of them aborts; can also run standalone / in CI:  python -I scripts/guard-unmanaged-attribute-policy.py
"""
import os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SELF = os.path.abspath(__file__)
EXT = (".sh", ".py", ".ps1", ".json", ".yml", ".yaml", ".env", ".properties")
# "unmanagedAttributePolicy":"ENABLED" | ["unmanagedAttributePolicy"] = "ENABLED" | unmanagedAttributePolicy=ENABLED ...
PATTERN = re.compile(r"unmanagedAttributePolicy[\"'\]\s]*[:=]\s*[\"']?ENABLED\b")


def violations():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", "node_modules", "target")]
        for name in filenames:
            path = os.path.join(dirpath, name)
            if not name.endswith(EXT) or os.path.abspath(path) == SELF:
                continue
            with open(path, encoding="utf-8", errors="replace") as f:
                for n, line in enumerate(f, 1):
                    if PATTERN.search(line):
                        yield os.path.relpath(path, ROOT), n, line.strip()


def main():
    found = list(violations())
    for path, n, line in found:
        print(f"FORBIDDEN unmanagedAttributePolicy=ENABLED  {path}:{n}: {line[:160]}", file=sys.stderr)
    if found:
        sys.exit("abort: users could self-edit tenant_id/continuum_user_id - use ADMIN_EDIT (read-modify-write of /users/profile)")
    print("guard: unmanagedAttributePolicy never set to ENABLED")


if __name__ == "__main__":
    main()
