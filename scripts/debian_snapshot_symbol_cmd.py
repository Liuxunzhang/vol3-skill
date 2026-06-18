#!/usr/bin/env python3
"""Generate Debian snapshot download and dwarf2json commands for Volatility3 symbols."""

from __future__ import annotations

import argparse
import html.parser
import json
import re
import os
import stat
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass


SNAPSHOT = "https://snapshot.debian.org"
DEFAULT_DWARF2JSON_URL = "https://github.com/volatilityfoundation/dwarf2json/releases/download/v0.9.0/dwarf2json-linux-amd64"


@dataclass(frozen=True)
class Candidate:
    package: str
    version: str
    arch: str
    filename: str
    url: str


class LinkParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        for name, value in attrs:
            if name == "href" and value:
                self.links.append(value)


def fetch_text(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "vol3-memory-analysis-skill"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8", errors="replace")


def fetch_json(url: str) -> object:
    return json.loads(fetch_text(url))


def release_candidates(release: str) -> list[str]:
    candidates = [release]
    # uname -r may contain Debian localversion text like
    # 6.12.90+deb13.1-amd64 while the package name uses
    # linux-image-6.12.90+deb13-amd64-dbg.
    normalized = re.sub(r"(\+deb\d+)\.\d+(-)", r"\1\2", release)
    if normalized != release:
        candidates.append(normalized)
    return list(dict.fromkeys(candidates))


def infer_package_revisions(release: str) -> list[str]:
    match = re.match(r"^([0-9][^-+]*)\+deb\d+\.(\d+)-", release)
    if match:
        base = match.group(1)
        local_revision = int(match.group(2))
        return [f"{base}-{value}" for value in range(local_revision, local_revision + 3)]
    return []


def package_names(kernel_release: str) -> list[str]:
    return [
        f"linux-image-{kernel_release}-dbgsym",
        f"linux-image-{kernel_release}-dbg",
    ]


def expected_filenames(package: str, version: str, arch: str) -> list[str]:
    versions = [version]
    if ":" in version:
        versions.append(version.split(":", 1)[1])
    return [f"{package}_{candidate}_{arch}.deb" for candidate in dict.fromkeys(versions)]


def parse_links(html: str) -> list[str]:
    parser = LinkParser()
    parser.feed(html)
    return parser.links


def absolutize(href: str) -> str:
    return urllib.parse.urljoin(SNAPSHOT + "/", href)


def candidate_from_url(package: str, version: str, arch: str, url: str) -> Candidate | None:
    filename = urllib.parse.unquote(url.rstrip("/").split("/")[-1])
    if filename in expected_filenames(package, version, arch):
        return Candidate(package, version, arch, filename, url)
    return None


def find_from_binary_page(package: str, version: str, arch: str) -> Candidate | None:
    url = f"{SNAPSHOT}/binary/{urllib.parse.quote(package)}/"
    html = fetch_text(url)
    for href in parse_links(html):
        absolute = absolutize(href)
        candidate = candidate_from_url(package, version, arch, absolute)
        if candidate:
            return candidate
        if f"/package/" in absolute and f"/{urllib.parse.quote(version, safe='')}/" in absolute:
            candidate = find_from_package_page(package, version, arch, absolute)
            if candidate:
                return candidate
    return None


def find_from_package_page(package: str, version: str, arch: str, url: str) -> Candidate | None:
    html = fetch_text(url.split("#", 1)[0])
    for href in parse_links(html):
        absolute = absolutize(href)
        candidate = candidate_from_url(package, version, arch, absolute)
        if candidate:
            return candidate
    return None


def find_from_machine_api(package: str, version: str, arch: str) -> Candidate | None:
    quoted_package = urllib.parse.quote(package, safe="")
    quoted_version = urllib.parse.quote(version, safe="")
    endpoints = [
        f"{SNAPSHOT}/mr/binary/{quoted_package}/{quoted_version}/binfiles",
        f"{SNAPSHOT}/mr/binary/{quoted_package}/",
    ]
    filenames = set(expected_filenames(package, version, arch))

    for endpoint in endpoints:
        try:
            data = fetch_json(endpoint)
        except Exception:
            continue
        stack = [data]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                values = [str(value) for value in item.values() if isinstance(value, str)]
                joined = " ".join(values)
                for filename in filenames:
                    if filename not in joined:
                        continue
                    for value in values:
                        if "/archive/" in value and filename in value:
                            return Candidate(package, version, arch, filename, absolutize(value))
                    if "hash" in item:
                        # Snapshot file endpoint redirects to the concrete archive URL.
                        file_url = f"{SNAPSHOT}/file/{item['hash']}"
                        return Candidate(package, version, arch, filename, file_url)
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
    return None


def resolve(package: str, version: str, arch: str) -> Candidate | None:
    for resolver in (find_from_binary_page, find_from_machine_api):
        try:
            candidate = resolver(package, version, arch)
        except Exception:
            candidate = None
        if candidate:
            return candidate
    return None


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._+-]+", "_", value)


def print_commands(
    candidate: Candidate,
    requested_release: str,
    matched_release: str,
    symbols_dir: str,
    build_dir: str,
    dwarf2json_url: str,
    script_out: str | None,
) -> None:
    base = safe_name(f"Debian_{requested_release}_{candidate.version}_{candidate.arch}")
    deb_path = f"{build_dir}/{candidate.filename}"
    extract_dir = f"{build_dir}/extract"
    tools_dir = f"{build_dir}/tools"
    dwarf2json_path = f"{tools_dir}/dwarf2json"
    json_path = f"{build_dir}/{base}.json"
    isf_path = f"{json_path}.xz"

    vmlinux_find = (
        "VMLINUX=$(find "
        f"{shell_quote(extract_dir)} "
        "-type f \\( "
        f"-name {shell_quote('vmlinux-' + requested_release)} -o "
        f"-name {shell_quote('vmlinux-' + matched_release)} -o "
        "-name 'vmlinux-*' "
        "\\) -print -quit)"
    )
    system_map_find = (
        "SYSTEM_MAP=$(find "
        f"{shell_quote(extract_dir)} "
        "-type f \\( "
        f"-name {shell_quote('System.map-' + requested_release)} -o "
        f"-name {shell_quote('System.map-' + matched_release)} -o "
        "-name 'System.map-*' "
        "\\) -print -quit)"
    )

    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        f"# Requested uname/kernel release: {requested_release}",
        f"# Matched package release: {matched_release}",
        f"# Package: {candidate.package}",
        f"# Version: {candidate.version}",
        f"# Snapshot URL: {candidate.url}",
        f"# dwarf2json URL: {dwarf2json_url}",
        "",
        f"mkdir -p {shell_quote(build_dir)} {shell_quote(symbols_dir)} {shell_quote(tools_dir)}",
        f"wget -O {shell_quote(deb_path)} {shell_quote(candidate.url)}",
        f"wget -O {shell_quote(dwarf2json_path)} {shell_quote(dwarf2json_url)}",
        f"chmod +x {shell_quote(dwarf2json_path)}",
        f"dpkg-deb -x {shell_quote(deb_path)} {shell_quote(extract_dir)}",
        vmlinux_find,
        system_map_find,
        'test -n "$VMLINUX"',
        'test -n "$SYSTEM_MAP"',
        f"{shell_quote(dwarf2json_path)} linux --elf \"$VMLINUX\" --system-map \"$SYSTEM_MAP\" > {shell_quote(json_path)}",
        f"xz -T0 -f {shell_quote(json_path)}",
        f"cp {shell_quote(isf_path)} {shell_quote(symbols_dir + '/')}",
        f"printf 'Generated ISF: %s\\n' {shell_quote(os.path.join(symbols_dir, os.path.basename(isf_path)))}",
    ]

    if script_out:
        parent = os.path.dirname(os.path.abspath(script_out))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(script_out, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        current = os.stat(script_out).st_mode
        os.chmod(script_out, current | stat.S_IXUSR)
        print(f"# Wrote executable script: {script_out}")
        print(f"bash {shell_quote(script_out)}")
        return

    print("\n".join(lines))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Find a Debian snapshot debug package and print ISF export commands."
    )
    release_group = parser.add_mutually_exclusive_group(required=True)
    release_group.add_argument("--kernel-release", help="Debian package kernel release, example: 6.1.0-18-amd64")
    release_group.add_argument("--uname-release", help="Raw uname -r output, example: 6.12.90+deb13.1-amd64")
    parser.add_argument(
        "--package-revision",
        help="Debian source/binary package version, example: 6.1.76-1. Prefer the exact value from the kernel banner, such as Debian 6.12.90-2.",
    )
    parser.add_argument("--arch", default="amd64", help="Debian architecture, default: amd64")
    parser.add_argument(
        "--symbols-dir",
        required=True,
        help="Volatility3 symbols/linux directory to receive the generated .json.xz.",
    )
    parser.add_argument("--build-dir", default="./vol3-symbol-build")
    parser.add_argument(
        "--dwarf2json-url",
        default=DEFAULT_DWARF2JSON_URL,
        help="Prebuilt dwarf2json binary URL to use in generated commands.",
    )
    parser.add_argument(
        "--script-out",
        help="Write the generated command sequence to an executable shell script instead of printing only.",
    )
    args = parser.parse_args()

    requested_release = args.uname_release or args.kernel_release
    package_revisions = [args.package_revision] if args.package_revision else infer_package_revisions(requested_release)
    if not package_revisions:
        print("ERROR: --package-revision is required when it cannot be inferred from the release.", file=sys.stderr)
        return 2

    tried: list[str] = []
    for candidate_release in release_candidates(requested_release):
        for package_revision in package_revisions:
            for package in package_names(candidate_release):
                tried.append(f"{package}={package_revision}")
                candidate = resolve(package, package_revision, args.arch)
                if candidate:
                    print_commands(
                        candidate,
                        requested_release,
                        candidate_release,
                        args.symbols_dir,
                        args.build_dir,
                        args.dwarf2json_url,
                        args.script_out,
                    )
                    return 0

    for package in package_names(requested_release):
        for package_revision in package_revisions:
            item = f"{package}={package_revision}"
            if item not in tried:
                tried.append(item)

    print("ERROR: no matching Debian snapshot debug package was found.", file=sys.stderr)
    print("Tried packages:", ", ".join(tried), file=sys.stderr)
    print("Check the kernel release, package revision, and architecture.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
