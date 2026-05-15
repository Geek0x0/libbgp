#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PUBLIC_HEADERS = [
    "include/libbgp/alloc.h",
    "include/libbgp/capability.h",
    "include/libbgp/event.h",
    "include/libbgp/filter.h",
    "include/libbgp/fsm.h",
    "include/libbgp/keepalive.h",
    "include/libbgp/libbgp.h",
    "include/libbgp/log.h",
    "include/libbgp/notification.h",
    "include/libbgp/open.h",
    "include/libbgp/out_handler.h",
    "include/libbgp/packet.h",
    "include/libbgp/pattr.h",
    "include/libbgp/prefix4.h",
    "include/libbgp/prefix6.h",
    "include/libbgp/rib4.h",
    "include/libbgp/rib6.h",
    "include/libbgp/sink.h",
    "include/libbgp/types.h",
    "include/libbgp/update.h",
]

INTERNAL_HEADERS = [
    "src/attr_view.h",
    "src/hashmap.h",
    "src/internal.h",
    "src/radix4.h",
    "src/radix6.h",
    "src/rib_internal.h",
    "src/vec.h",
]

SOURCE_FILES = [
    "src/alloc.c",
    "src/capability.c",
    "src/errcode.c",
    "src/event.c",
    "src/filter.c",
    "src/fsm.c",
    "src/hashmap.c",
    "src/keepalive.c",
    "src/log.c",
    "src/notification.c",
    "src/open.c",
    "src/out_handler.c",
    "src/packet.c",
    "src/pattr.c",
    "src/prefix4.c",
    "src/prefix6.c",
    "src/radix4.c",
    "src/radix6.c",
    "src/rib4.c",
    "src/rib6.c",
    "src/sink.c",
    "src/update.c",
]

GROUPS = {
    "alloc.h": "libbgp_core",
    "capability.h": "libbgp_packet",
    "event.h": "libbgp_event",
    "filter.h": "libbgp_filter",
    "fsm.h": "libbgp_fsm",
    "keepalive.h": "libbgp_messages",
    "log.h": "libbgp_core",
    "notification.h": "libbgp_messages",
    "open.h": "libbgp_messages",
    "out_handler.h": "libbgp_io",
    "packet.h": "libbgp_packet",
    "pattr.h": "libbgp_packet",
    "prefix4.h": "libbgp_prefix",
    "prefix6.h": "libbgp_prefix",
    "rib4.h": "libbgp_rib",
    "rib6.h": "libbgp_rib",
    "sink.h": "libbgp_io",
    "types.h": "libbgp_core",
    "update.h": "libbgp_messages",
}

DOXY_REQUIRED = {
    "INPUT": "./include/libbgp ./src README.md",
    "EXTRACT_ALL": "YES",
    "EXTRACT_STATIC": "YES",
    "WARN_AS_ERROR": "FAIL_ON_WARNINGS",
    "QUIET": "YES",
    "GENERATE_LATEX": "NO",
    "GENERATE_MAN": "NO",
}

PUBLIC_DECL_RE = re.compile(
    r"/\*\*(?P<doc>.*?)\*/\s*"
    r"LIBBGP_API\s+"
    r"(?P<decl>[^;]+;)",
    re.DOTALL,
)

PARAM_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]+\])?$")


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def doxy_value(text: str, key: str) -> str | None:
    match = re.search(rf"^{re.escape(key)}\s*=\s*(.*?)$", text, re.MULTILINE)
    return match.group(1).strip() if match else None


def function_params(decl: str) -> list[str]:
    start = decl.find("(")
    end = decl.rfind(")")
    if start < 0 or end < start:
        return []
    params = decl[start + 1 : end].strip()
    if params in ("", "void"):
        return []
    names: list[str] = []
    for raw in params.split(","):
        raw = raw.strip()
        raw = raw.replace("const ", "").replace("volatile ", "")
        raw = raw.replace("*", " ")
        parts = raw.split()
        if not parts:
            continue
        match = PARAM_RE.search(parts[-1])
        if match:
            names.append(match.group(1))
    return names


def function_returns_value(decl: str) -> bool:
    prefix = decl.split("(", 1)[0]
    prefix = prefix.replace("LIBBGP_API", "").strip()
    return not prefix.startswith("void ")


def check_doxyfile(errors: list[str]) -> None:
    text = read("Doxyfile")
    for key, expected in DOXY_REQUIRED.items():
        actual = doxy_value(text, key)
        if actual != expected:
            fail(errors, f"Doxyfile: expected {key} = {expected!r}, found {actual!r}")
    if not re.search(r"^FILE_PATTERNS\s*=.*\*\.h", text, re.MULTILINE | re.DOTALL):
        fail(errors, "Doxyfile: FILE_PATTERNS must include *.h")
    if not re.search(r"^FILE_PATTERNS\s*=.*\*\.c", text, re.MULTILINE | re.DOTALL):
        fail(errors, "Doxyfile: FILE_PATTERNS must include *.c")


def check_file_blocks(errors: list[str]) -> None:
    for path in PUBLIC_HEADERS + INTERNAL_HEADERS + SOURCE_FILES:
        text = read(path)
        name = Path(path).name
        if f"@file {name}" not in text:
            fail(errors, f"{path}: missing @file {name}")
        if "@brief" not in text:
            fail(errors, f"{path}: missing @brief")


def check_groups(errors: list[str]) -> None:
    for path in PUBLIC_HEADERS:
        name = Path(path).name
        text = read(path)
        if name == "libbgp.h":
            for group in sorted(set(GROUPS.values())):
                if f"@defgroup {group}" not in text:
                    fail(errors, f"{path}: missing @defgroup {group}")
        else:
            group = GROUPS[name]
            if f"@ingroup {group}" not in text:
                fail(errors, f"{path}: missing @ingroup {group}")


def check_public_functions(errors: list[str]) -> None:
    for path in PUBLIC_HEADERS:
        if path.endswith("libbgp.h"):
            continue
        text = read(path)
        decls = re.findall(r"LIBBGP_API\s+[^;]+;", text, re.DOTALL)
        documented = {m.group("decl").strip() for m in PUBLIC_DECL_RE.finditer(text)}
        for decl in decls:
            normalized = " ".join(decl.split())
            matching_doc = None
            for match in PUBLIC_DECL_RE.finditer(text):
                if " ".join(match.group("decl").split()) == normalized:
                    matching_doc = match.group("doc")
                    break
            if matching_doc is None:
                fail(errors, f"{path}: missing Doxygen block for {normalized}")
                continue
            if "@brief" not in matching_doc:
                fail(errors, f"{path}: missing @brief for {normalized}")
            for param in function_params(decl):
                if f"@param {param}" not in matching_doc and f"@param[out] {param}" not in matching_doc and f"@param[in,out] {param}" not in matching_doc:
                    fail(errors, f"{path}: missing @param for {param} in {normalized}")
            if function_returns_value(decl) and "@return" not in matching_doc:
                fail(errors, f"{path}: missing @return for {normalized}")


def main() -> int:
    errors: list[str] = []
    check_doxyfile(errors)
    check_file_blocks(errors)
    check_groups(errors)
    check_public_functions(errors)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("Doxygen documentation checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
