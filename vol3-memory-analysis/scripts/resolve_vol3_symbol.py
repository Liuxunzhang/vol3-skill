#!/usr/bin/env python3
"""Resolve or download Volatility3 ISF files from Abyss-W4tcher symbols."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass


REPO = "Abyss-W4tcher/volatility3-symbols"
BRANCH = "master"
API_BASE = f"https://api.github.com/repos/{REPO}"
RAW_BASE = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/"
HTML_RAW_BASE = f"https://github.com/{REPO}/raw/{BRANCH}/"
DEFAULT_BANNERS_URL = f"{RAW_BASE}banners/banners_plain.json"


@dataclass(frozen=True)
class SymbolMatch:
    path: str
    download_url: str
    reason: str


def request(url: str) -> urllib.request.Request:
    return urllib.request.Request(url, headers={"User-Agent": "vol3-memory-analysis-skill"})


def fetch_json(url: str) -> object:
    with urllib.request.urlopen(request(url), timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def normalize(value: str) -> str:
    return " ".join(value.strip().split())


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def raw_url(path: str) -> str:
    return RAW_BASE + urllib.parse.quote(path, safe="/._-+~")


def contents_url(path: str) -> str:
    quoted = urllib.parse.quote(path.strip("/"), safe="/")
    return f"{API_BASE}/contents/{quoted}?ref={BRANCH}"


def tree_url(sha_or_path: str) -> str:
    return f"{API_BASE}/git/trees/{urllib.parse.quote(sha_or_path, safe='')}?recursive=1"


def find_banner_matches(mapping: dict[str, list[str]], banner: str) -> list[SymbolMatch]:
    wanted = normalize(banner)
    exact: list[SymbolMatch] = []
    contains: list[SymbolMatch] = []

    for key, paths in mapping.items():
        normalized_key = normalize(key)
        target = exact if normalized_key == wanted else contains
        if normalized_key == wanted or wanted in normalized_key or normalized_key in wanted:
            for path in paths:
                target.append(SymbolMatch(path=path, download_url=raw_url(path), reason=f"banner: {key}"))

    return exact or contains


def filename_parts(filename: str) -> tuple[str, str, str] | None:
    name = filename.removesuffix(".json.xz")
    parts = name.split("_")
    if len(parts) < 4:
        return None
    distro = parts[0]
    kernel_release = parts[1]
    arch = parts[-1]
    return distro, kernel_release, arch


def kernel_base_version(kernel_release: str) -> str | None:
    match = re.match(r"^(\d+\.\d+\.\d+)", kernel_release)
    if match:
        return match.group(1)
    match = re.match(r"^(\d+\.\d+)", kernel_release)
    if match:
        return match.group(1)
    return None


def collect_files_from_contents(path: str) -> list[dict[str, object]]:
    data = fetch_json(contents_url(path))
    if isinstance(data, dict) and data.get("type") == "file":
        return [data]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def find_in_directory(path: str, filename: str) -> SymbolMatch | None:
    for item in collect_files_from_contents(path):
        if item.get("type") == "file" and item.get("name") == filename:
            download_url = str(item.get("download_url") or raw_url(str(item["path"])))
            return SymbolMatch(path=str(item["path"]), download_url=download_url, reason=f"contents: {path}")
    return None


def find_with_subtree(path: str, filename: str) -> SymbolMatch | None:
    data = fetch_json(contents_url(path))
    if isinstance(data, dict):
        git_url = data.get("git_url")
    else:
        git_url = None
    if not git_url:
        return None

    tree = fetch_json(str(git_url) + "?recursive=1")
    if not isinstance(tree, dict):
        return None
    for item in tree.get("tree", []):
        if not isinstance(item, dict) or item.get("type") != "blob":
            continue
        item_path = str(item.get("path", ""))
        if item_path.endswith("/" + filename) or item_path == filename:
            full_path = f"{path.strip('/')}/{item_path}"
            return SymbolMatch(path=full_path, download_url=raw_url(full_path), reason=f"tree: {path}")
    return None


def find_by_filename(filename: str, root: str | None = None) -> list[SymbolMatch]:
    probes: list[str] = []
    parts = filename_parts(filename)
    if root:
        probes.append(root.strip("/"))
    if parts:
        distro, kernel_release, arch = parts
        base = kernel_base_version(kernel_release)
        if base:
            probes.append(f"{distro}/{arch}/{base}")
        probes.append(f"{distro}/{arch}")
        probes.append(distro)

    matches: list[SymbolMatch] = []
    for probe in list(dict.fromkeys(probes)):
        try:
            direct = find_in_directory(probe, filename)
            if direct:
                matches.append(direct)
                break
        except Exception:
            pass
        try:
            tree_match = find_with_subtree(probe, filename)
            if tree_match:
                matches.append(tree_match)
                break
        except Exception:
            pass
    return matches


def download(match: SymbolMatch, symbols_dir: str) -> str:
    os.makedirs(symbols_dir, exist_ok=True)
    target = os.path.join(symbols_dir, os.path.basename(match.path))
    with urllib.request.urlopen(request(match.download_url), timeout=120) as response:
        with open(target, "wb") as output:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                output.write(chunk)
    return target


def print_matches(matches: list[SymbolMatch], symbols_dir: str) -> None:
    print(f"# Matched {len(matches)} symbol candidate(s).")
    print(f"mkdir -p {shell_quote(symbols_dir)}")
    for match in matches:
        print()
        print(f"# Source: {match.reason}")
        print(f"# Path: {match.path}")
        print(f"wget -O {shell_quote(os.path.join(symbols_dir, os.path.basename(match.path)))} {shell_quote(match.download_url)}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Resolve or download Volatility3 ISF files from Abyss-W4tcher/volatility3-symbols."
    )
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument("--banner", help="Exact or partial kernel banner.")
    selector.add_argument("--filename", help="Exact .json.xz symbol filename to locate.")
    parser.add_argument(
        "--symbols-dir",
        required=True,
        help="Volatility3 symbols/linux directory to receive the .json.xz file.",
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Download matched symbol file(s) instead of only printing wget commands.",
    )
    parser.add_argument(
        "--search-root",
        help="Optional repository directory to search first, such as KaliLinux/amd64/6.9.11.",
    )
    parser.add_argument(
        "--banners-url",
        default=DEFAULT_BANNERS_URL,
        help="Banner mapping URL. Defaults to the public volatility3-symbols raw mapping.",
    )
    args = parser.parse_args()

    try:
        if args.banner:
            mapping = fetch_json(args.banners_url)
            if not isinstance(mapping, dict):
                raise ValueError("banner mapping was not a JSON object")
            matches = find_banner_matches(mapping, args.banner)
        else:
            matches = find_by_filename(args.filename, root=args.search_root)
    except Exception as exc:
        print(f"ERROR: symbol lookup failed: {exc}", file=sys.stderr)
        return 2

    if not matches:
        print("No ISF match found.", file=sys.stderr)
        if args.filename:
            print("Check the filename, distro prefix, architecture, or pass --search-root.", file=sys.stderr)
        else:
            print("Next: generate symbols manually or try Volatility3 --remote-isf-url.", file=sys.stderr)
        return 1

    print_matches(matches, args.symbols_dir)

    if args.download:
        print()
        for match in matches:
            target = download(match, args.symbols_dir)
            print(f"# Downloaded: {target}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
