#!/usr/bin/env python3
"""Merge realm fragments (realms/*.fragment.json) into a Keycloak realm export, idempotently.

Usage: python -I merge-fragments.py REALM.json FRAGMENT.json [FRAGMENT.json ...] [-o OUT.json]

Lists are merged by natural key (an entry with the same key is REPLACED, new ones appended):
clients/clientId, authenticationFlows/alias, authenticatorConfig/alias, users/username,
clientScopes/name, scopeMappings/client, roles.realm/name. "attributes" dicts are updated key by key. "_comment" is ignored. Any other key in a fragment is an error (no silent merge).
Output keeps the realm file format: UTF-8 (no ASCII escaping), indent 2, original line endings.
Secrets stay as ${ENV} placeholders (Keycloak substitutes them at --import-realm).
"""
import argparse
import json
import sys

KEYS = {
    "clients": "clientId",
    "authenticationFlows": "alias",
    "authenticatorConfig": "alias",
    "users": "username",
    "clientScopes": "name",
    "scopeMappings": "client",
}


def merge_list(target, entries, nk):
    index = {e.get(nk): i for i, e in enumerate(target)}
    for entry in entries:
        if entry.get(nk) in index:
            target[index[entry[nk]]] = entry
        else:
            index[entry[nk]] = len(target)
            target.append(entry)


def merge(realm, fragment, name):
    for key, value in fragment.items():
        if key == "_comment":
            continue
        if key == "attributes":
            realm.setdefault("attributes", {}).update(value)
        elif key in KEYS:
            merge_list(realm.setdefault(key, []), value, KEYS[key])
        elif key == "roles" and set(value) == {"realm"}:
            merge_list(realm.setdefault("roles", {}).setdefault("realm", []), value["realm"], "name")
        else:
            sys.exit(f"{name}: unsupported fragment key '{key}'")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("realm")
    p.add_argument("fragments", nargs="+")
    p.add_argument("-o", "--out", help="output file (default: overwrite REALM)")
    a = p.parse_args()
    raw = open(a.realm, "rb").read()
    newline = "\r\n" if b"\r\n" in raw else "\n"
    realm = json.loads(raw.decode("utf-8-sig"))
    for f in a.fragments:
        with open(f, encoding="utf-8") as fh:
            merge(realm, json.load(fh), f)
    text = json.dumps(realm, indent=2, ensure_ascii=False) + "\n"
    with open(a.out or a.realm, "w", encoding="utf-8", newline=newline) as fh:
        fh.write(text)


if __name__ == "__main__":
    main()
