#!/usr/bin/env python3
"""
Local import health-check: tries to import adapters and parsers and prints summary.
Exits 0 even if imports fail (so it's tolerant).
"""
import importlib, pkgutil, os, sys

failures = []

base = os.path.join(os.getcwd(), "modules")
def try_import(name):
    try:
        importlib.import_module(name)
        print("OK:", name)
    except Exception as e:
        failures.append((name, str(e)))
        print("WARN:", name, e)

if os.path.isdir(os.path.join(base, "tools")):
    tools_dir = os.path.join(base, "tools")
    for finder, modname, ispkg in pkgutil.iter_modules([tools_dir]):
        if modname == "parsers":
            continue
        try_import("modules.tools." + modname)
    ad_dir = os.path.join(tools_dir, "adapters")
    if os.path.isdir(ad_dir):
        for finder, modname, ispkg in pkgutil.iter_modules([ad_dir]):
            try_import("modules.tools.adapters." + modname)

if os.path.isdir(os.path.join(base, "parsers")):
    parsers_dir = os.path.join(base, "parsers")
    for finder, modname, ispkg in pkgutil.iter_modules([parsers_dir]):
        try_import("modules.parsers." + modname)

print("Finished import check. failures:", len(failures))
