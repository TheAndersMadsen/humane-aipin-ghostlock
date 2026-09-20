#!/usr/bin/env python3
"""Derive a boot-scoped arm64 KASLR base from an Android bugreport.

Only the root-level bugreport text member and its current SYSTEM LOG kernel
buffer are considered.  Archived logcat files in the ZIP are deliberately
ignored because they can contain WARN records from older boots.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path


KASLR_ALIGNMENT = 0x200000
KIMAGE_MIN = 0xFFFFFF8000000000
KIMAGE_MAX = 0xFFFFFFC000000000


class KaslrParseError(RuntimeError):
    pass


@dataclass(frozen=True)
class Anchor:
    role: str
    symbol: str
    offset: int
    link_address: int
    runtime_address: int
    slide: int
    report_line: int


@dataclass(frozen=True)
class KaslrResult:
    report_member: str
    text_base_symbol: str
    link_text_base: int
    runtime_text_base: int
    slide: int
    anchors: tuple[Anchor, ...]


SYMBOL_LINE_RE = re.compile(
    r"^(?P<address>[0-9a-fA-F]{16})\s+\S\s+(?P<name>\S+)$"
)
ROLE_RE = re.compile(
    r"\b(?P<role>pc|lr)\s*:\s*(?P<symbol>[A-Za-z0-9_.$]+)"
    r"\+0x(?P<offset>[0-9a-fA-F]+)/0x[0-9a-fA-F]+",
    re.IGNORECASE,
)
DUMP_HEADER_RE = re.compile(
    r"\b(?P<role>PC|LR)\s*:\s*0x(?P<address>[0-9a-fA-F]{16}):"
)
STACK_WORDS_RE = re.compile(
    r"(?:^|[:\]])\s*[0-9a-fA-F]{4}\s+"
    r"(?P<words>(?:[0-9a-fA-F]{8}\s+){7}"
    r"[0-9a-fA-F]{8})(?:\s|$)"
)


def load_symbols(path: Path) -> dict[str, int]:
    symbols: dict[str, int] = {}
    ambiguous: set[str] = set()
    with path.open("r", encoding="utf-8", errors="strict") as handle:
        for line in handle:
            match = SYMBOL_LINE_RE.match(line.rstrip("\n"))
            if not match:
                continue
            name = match.group("name")
            address = int(match.group("address"), 16)
            previous = symbols.get(name)
            if previous is not None and previous != address:
                # Kallsyms legitimately contains duplicate local symbol names.
                # Remove ambiguous names entirely so they can never be selected
                # as a trusted anchor.
                ambiguous.add(name)
            elif name not in ambiguous:
                symbols[name] = address
    for name in ambiguous:
        symbols.pop(name, None)
    if "_text" not in symbols:
        raise KaslrParseError(f"{path} does not contain _text")
    return symbols


def _read_report(zip_path: Path) -> tuple[str, str]:
    try:
        with zipfile.ZipFile(zip_path) as archive:
            members = [
                info
                for info in archive.infolist()
                if "/" not in info.filename.rstrip("/")
                and info.filename.startswith("bugreport-")
                and info.filename.endswith(".txt")
            ]
            if len(members) != 1:
                names = ", ".join(info.filename for info in members) or "none"
                raise KaslrParseError(
                    "expected exactly one root-level bugreport text member; "
                    f"found {names}"
                )
            info = members[0]
            data = archive.read(info)
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        raise KaslrParseError(f"cannot read bugreport ZIP {zip_path}: {exc}") from exc
    return info.filename, data.decode("utf-8", "replace")


def _kernel_section(report: str) -> tuple[list[str], int]:
    lines = report.splitlines()

    # Retail dumpstate exposes the live printk ring directly.  Prefer it when
    # present because it is both current and independent of logd buffering.
    for section_start, line in enumerate(lines):
        if not line.startswith("------ KERNEL LOG (dmesg) ------"):
            continue
        section_end = len(lines)
        for index in range(section_start + 1, len(lines)):
            if lines[index].startswith("------ "):
                section_end = index
                break
        if section_end <= section_start + 1:
            raise KaslrParseError("current KERNEL LOG section is empty")
        return lines[section_start + 1:section_end], section_start + 1

    system_log = None
    for index, line in enumerate(lines):
        if line.startswith("------ SYSTEM LOG ("):
            system_log = index
            break
    if system_log is None:
        raise KaslrParseError("current SYSTEM LOG section was not found")

    system_log_end = len(lines)
    for index in range(system_log + 1, len(lines)):
        line = lines[index]
        if line.startswith("------ "):
            system_log_end = index
            break

    # Userdebug logd emits a dedicated ``beginning of kernel`` buffer.  The
    # retail build folds printk records into the current ``main`` buffer.  In
    # both cases the enclosing SYSTEM LOG is captured live by dumpstate; never
    # scan archived logcat members from the ZIP.
    kernel_start = None
    for index in range(system_log + 1, system_log_end):
        if lines[index].strip() == "--------- beginning of kernel":
            kernel_start = index + 1
            break
    if kernel_start is None:
        return lines[system_log + 1:system_log_end], system_log + 1

    kernel_end = system_log_end
    for index in range(kernel_start, system_log_end):
        if lines[index].startswith("--------- beginning of "):
            kernel_end = index
            break
    if kernel_end <= kernel_start:
        raise KaslrParseError("current SYSTEM LOG kernel buffer is empty")
    return lines[kernel_start:kernel_end], kernel_start


def _valid_slide(runtime: int, link_runtime: int) -> int | None:
    if not (KIMAGE_MIN <= runtime < KIMAGE_MAX) or runtime < link_runtime:
        return None
    slide = runtime - link_runtime
    if slide % KASLR_ALIGNMENT:
        return None
    runtime_base = KIMAGE_MIN + slide
    if not (KIMAGE_MIN <= runtime_base < KIMAGE_MAX):
        return None
    return slide


def _stack_qwords(block: list[str]) -> set[int]:
    qwords: set[int] = set()
    in_stack_dump = False
    for line in block:
        if re.search(r"\bSP\s*:\s*0x[0-9a-fA-F]{16}:", line):
            in_stack_dump = True
            continue
        if not in_stack_dump:
            continue
        if "Call trace:" in line or "---[ end trace" in line:
            break
        match = STACK_WORDS_RE.search(line)
        if not match:
            continue
        words = [int(word, 16) for word in match.group("words").split()]
        for index in range(0, len(words), 2):
            qwords.add(words[index] | (words[index + 1] << 32))
    return qwords


def _warn_blocks(lines: list[str]) -> list[tuple[int, list[str]]]:
    blocks: list[tuple[int, list[str]]] = []
    index = 0
    while index < len(lines):
        if "WARNING: CPU:" not in lines[index]:
            index += 1
            continue
        start = index
        end = min(len(lines), start + 160)
        for cursor in range(start, end):
            if "---[ end trace" in lines[cursor]:
                end = cursor + 1
                break
        blocks.append((start, lines[start:end]))
        index = end
    return blocks


def parse_bugreport(
    zip_path: Path,
    symbols_path: Path,
    *,
    expected_boot_id: str | None = None,
    expected_serial: str | None = None,
    expected_fingerprint: str | None = None,
) -> KaslrResult:
    symbols = load_symbols(symbols_path)
    member, report = _read_report(zip_path)

    if expected_boot_id and f"linuxBootId={expected_boot_id}" not in report:
        raise KaslrParseError(
            f"bugreport does not contain current boot ID {expected_boot_id}"
        )
    if expected_serial and f"androidboot.serialno={expected_serial}" not in report:
        raise KaslrParseError(
            f"bugreport command line does not name serial {expected_serial}"
        )
    if expected_fingerprint:
        fingerprint_line = f"Build fingerprint: '{expected_fingerprint}'"
        if fingerprint_line not in report:
            raise KaslrParseError(
                f"bugreport fingerprint does not match {expected_fingerprint}"
            )

    kernel_lines, report_offset = _kernel_section(report)
    anchors: list[Anchor] = []
    for block_start, block in _warn_blocks(kernel_lines):
        roles: dict[str, tuple[str, int]] = {}
        headers: dict[str, int] = {}
        for line in block:
            role_match = ROLE_RE.search(line)
            if role_match:
                role = role_match.group("role").upper()
                roles.setdefault(
                    role,
                    (
                        role_match.group("symbol"),
                        int(role_match.group("offset"), 16),
                    ),
                )
            header_match = DUMP_HEADER_RE.search(line)
            if header_match:
                headers[header_match.group("role").upper()] = int(
                    header_match.group("address"), 16
                )

        qwords = _stack_qwords(block)
        for role in ("PC", "LR"):
            if role not in roles or role not in headers:
                continue
            symbol, offset = roles[role]
            link_address = symbols.get(symbol)
            if link_address is None:
                continue
            # show_extra_register_data() prints a 0x80-byte window around the
            # register.  On this arm64 kernel the dump header begins 0x40
            # bytes before the exact PC/LR; require the exact value to also
            # appear in the SP register frame before trusting it.
            runtime = headers[role] + 0x40
            if runtime not in qwords:
                raise KaslrParseError(
                    f"{role} raw address 0x{runtime:016x} is absent from the "
                    f"WARN stack frame at report line {report_offset + block_start + 1}"
                )
            slide = _valid_slide(runtime, link_address + offset)
            if slide is None:
                raise KaslrParseError(
                    f"{role} anchor {symbol}+0x{offset:x} yields an invalid slide"
                )
            anchors.append(
                Anchor(
                    role=role,
                    symbol=symbol,
                    offset=offset,
                    link_address=link_address,
                    runtime_address=runtime,
                    slide=slide,
                    report_line=report_offset + block_start + 1,
                )
            )

    if len(anchors) < 2:
        raise KaslrParseError(
            f"only {len(anchors)} usable PC/LR WARN anchors were found; need at least 2"
        )
    distinct_symbols = {anchor.symbol for anchor in anchors}
    if len(distinct_symbols) < 2:
        raise KaslrParseError(
            "WARN anchors do not cover at least two independent symbols"
        )
    slides = {anchor.slide for anchor in anchors}
    if len(slides) != 1:
        details = ", ".join(
            f"{anchor.role}:{anchor.symbol}+0x{anchor.offset:x}=0x{anchor.slide:x}"
            for anchor in anchors
        )
        raise KaslrParseError(f"WARN anchors disagree on KASLR slide: {details}")

    slide = next(iter(slides))
    link_text = symbols["_text"]
    runtime_text = link_text + slide
    if runtime_text % 0x1000:
        raise KaslrParseError("derived runtime _text is not page aligned")
    return KaslrResult(
        report_member=member,
        text_base_symbol="_text",
        link_text_base=link_text,
        runtime_text_base=runtime_text,
        slide=slide,
        anchors=tuple(anchors),
    )


def _json_result(result: KaslrResult) -> dict[str, object]:
    value = asdict(result)
    value["link_text_base"] = f"0x{result.link_text_base:016x}"
    value["runtime_text_base"] = f"0x{result.runtime_text_base:016x}"
    value["slide"] = f"0x{result.slide:x}"
    value["anchors"] = [
        {
            **asdict(anchor),
            "offset": f"0x{anchor.offset:x}",
            "link_address": f"0x{anchor.link_address:016x}",
            "runtime_address": f"0x{anchor.runtime_address:016x}",
            "slide": f"0x{anchor.slide:x}",
        }
        for anchor in result.anchors
    ]
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bugreport", type=Path)
    parser.add_argument("--symbols", type=Path, required=True)
    parser.add_argument("--expected-boot-id")
    parser.add_argument("--expected-serial")
    parser.add_argument("--expected-fingerprint")
    parser.add_argument(
        "--format", choices=("human", "json", "value"), default="human"
    )
    args = parser.parse_args(argv)
    try:
        result = parse_bugreport(
            args.bugreport,
            args.symbols,
            expected_boot_id=args.expected_boot_id,
            expected_serial=args.expected_serial,
            expected_fingerprint=args.expected_fingerprint,
        )
    except KaslrParseError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.format == "value":
        print(f"0x{result.runtime_text_base:016x}")
    elif args.format == "json":
        print(json.dumps(_json_result(result), indent=2, sort_keys=True))
    else:
        print(f"report_member={result.report_member}")
        print(f"anchors={len(result.anchors)}")
        for anchor in result.anchors:
            print(
                f"anchor={anchor.role}:{anchor.symbol}+0x{anchor.offset:x} "
                f"link=0x{anchor.link_address:016x} "
                f"runtime=0x{anchor.runtime_address:016x} "
                f"slide=0x{anchor.slide:x} line={anchor.report_line}"
            )
        print(f"kaslr_slide=0x{result.slide:x}")
        print(f"kaslr_base=0x{result.runtime_text_base:016x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
