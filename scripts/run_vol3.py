#!/usr/bin/env python3
"""Run Volatility3 with workspace-local cache and symbols configured."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


EVIDENCE_START = "<!-- vol3-evidence:start -->"
EVIDENCE_END = "<!-- vol3-evidence:end -->"
CASE_INDEX = ".vol3-cases.json"
UNKNOWN_KERNEL = "_unidentified-kernel"


def resolve_volatility(workspace: Path, requested: str | None) -> Path:
    if requested:
        candidate = Path(requested).expanduser()
        if not candidate.is_absolute():
            candidate = workspace / candidate
        candidate = candidate.resolve()
        if not candidate.is_file():
            raise FileNotFoundError(f"Volatility entrypoint not found: {candidate}")
        return candidate

    local_entrypoint = workspace / ".venv/bin/vol"
    if local_entrypoint.is_file():
        return local_entrypoint

    for name in ("vol", "vol.py"):
        resolved = shutil.which(name)
        if resolved:
            return Path(resolved).resolve()

    raise FileNotFoundError(
        "Volatility entrypoint not found. Use --vol or create <workspace>/.venv/bin/vol."
    )


def workspace_path(workspace: Path, value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = workspace / path
    return path.resolve()


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-") or "result"


def safe_kernel_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._+-]+", "-", value).strip("-") or UNKNOWN_KERNEL


def renderer_extension(renderer: str | None) -> str:
    return {
        "csv": ".csv",
        "json": ".json",
        "jsonl": ".jsonl",
        "yaml": ".yaml",
    }.get((renderer or "").lower(), ".txt")


def file_identity(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {
        "path": str(path),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def symbol_identity(symbols: Path) -> list[dict[str, Any]]:
    return [
        file_identity(path)
        for path in sorted(symbols.rglob("*"))
        if path.is_file()
    ]


def load_case_index(results: Path) -> dict[str, str]:
    path = results / CASE_INDEX
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {
        str(key): str(value)
        for key, value in data.items()
        if isinstance(key, str) and isinstance(value, str)
    } if isinstance(data, dict) else {}


def save_case_index(results: Path, cases: dict[str, str]) -> None:
    path = results / CASE_INDEX
    temporary = path.with_name(path.name + ".part")
    temporary.write_text(
        json.dumps(cases, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def image_case_key(image: Path) -> str:
    identity = file_identity(image)
    return f"{identity['path']}|{identity['size']}|{identity['mtime_ns']}"


def kernel_from_banner_text(text: str) -> str | None:
    releases = re.findall(r"\bLinux version\s+([A-Za-z0-9._+-]+)", text)
    if not releases:
        return None
    counts = Counter(releases)
    return max(counts, key=lambda value: (counts[value], len(value)))


def windows_kernel_from_info_text(text: str) -> str | None:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2:
            fields[parts[0].strip()] = parts[1].strip()

    major = fields.get("NtMajorVersion")
    minor = fields.get("NtMinorVersion")
    kernel_version = fields.get("Major/Minor", "")
    build_match = re.fullmatch(r"\d+\.(\d+)", kernel_version)
    if not major or not minor or not build_match:
        return None

    product = {
        "NtProductServer": "server",
        "NtProductWinNt": "workstation",
        "NtProductLanManNt": "domain-controller",
    }.get(fields.get("NtProductType", ""), "unknown")
    return f"windows-{major}.{minor}.{build_match.group(1)}-{product}"


def is_legacy_windows_symbol_name(value: str) -> bool:
    return bool(re.fullmatch(r"[^/]+\.pdb-[0-9A-Fa-f]+-\d+", value))


def result_matches_image(result: Path, image: Path) -> bool:
    metadata = result.with_name(result.name + ".meta.json")
    if not metadata.is_file():
        return True
    try:
        record = json.loads(metadata.read_text(encoding="utf-8"))
        recorded_image = record.get("signature", {}).get("image", {})
    except (OSError, json.JSONDecodeError, AttributeError):
        return True
    recorded_path = recorded_image.get("path")
    return not recorded_path or Path(recorded_path) == image


def discover_kernel(results: Path, image: Path) -> str | None:
    key = image_case_key(image)
    cases = load_case_index(results)
    indexed = cases.get(key)
    if indexed and not is_legacy_windows_symbol_name(indexed):
        return indexed

    for banner in results.rglob(f"{safe_name(image.stem)}-banners.Banners*.txt"):
        if banner.name.endswith(".part") or ".failed." in banner.name:
            continue
        if not result_matches_image(banner, image):
            continue
        try:
            release = kernel_from_banner_text(
                banner.read_text(encoding="utf-8", errors="replace")
            )
        except OSError:
            continue
        if release:
            register_kernel(results, image, release)
            return release

    for info in results.rglob(f"{safe_name(image.stem)}-windows.info.Info*.txt"):
        if info.name.endswith(".part") or ".failed." in info.name:
            continue
        if not result_matches_image(info, image):
            continue
        try:
            release = windows_kernel_from_info_text(
                info.read_text(encoding="utf-8", errors="replace")
            )
        except OSError:
            continue
        if release:
            register_kernel(results, image, release)
            return release
    return indexed


def case_directory(results: Path, image: Path | None) -> Path:
    if image is None:
        return results / "_workspace"
    release = discover_kernel(results, image)
    if release:
        return results / safe_kernel_name(release)
    return results / UNKNOWN_KERNEL / safe_name(image.stem)


def register_kernel(results: Path, image: Path, release: str) -> Path:
    cases = load_case_index(results)
    previous_release = cases.get(image_case_key(image))
    cases[image_case_key(image)] = release
    save_case_index(results, cases)

    target = results / safe_kernel_name(release)
    target.mkdir(parents=True, exist_ok=True)
    sources = [results / UNKNOWN_KERNEL / safe_name(image.stem)]
    if previous_release and previous_release != release:
        sources.append(results / safe_kernel_name(previous_release))

    for source in sources:
        if not source.is_dir() or source == target:
            continue
        for item in source.iterdir():
            destination = target / item.name
            if destination.exists():
                raise ValueError(
                    f"Cannot classify result; destination exists: {destination}"
                )
            item.replace(destination)
        source.rmdir()
        if source.parent.name == UNKNOWN_KERNEL:
            unidentified = source.parent
            if unidentified.is_dir() and not any(unidentified.iterdir()):
                unidentified.rmdir()
    for metadata in target.glob("*.meta.json"):
        try:
            record = json.loads(metadata.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        result_path = Path(str(record.get("result", "")))
        relocated = target / result_path.name
        if result_path.name and relocated.exists() and result_path != relocated:
            record["result"] = str(relocated)
            metadata.write_text(
                json.dumps(record, indent=2, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
    return target


def result_paths(
    case_results: Path,
    image: Path | None,
    plugin: str,
    plugin_args: list[str],
    renderer: str | None,
) -> tuple[Path, Path]:
    image_name = safe_name(image.stem if image else "workspace")
    plugin_name = safe_name(plugin)
    variant = {
        "plugin_args": plugin_args,
        "renderer": renderer,
    }
    suffix = ""
    if plugin_args or renderer:
        digest = hashlib.sha256(
            json.dumps(variant, sort_keys=True).encode("utf-8")
        ).hexdigest()[:10]
        suffix = f"-{digest}"
    result = case_results / (
        f"{image_name}-{plugin_name}{suffix}{renderer_extension(renderer)}"
    )
    return result, result.with_name(result.name + ".meta.json")


def reusable_result(
    result: Path,
    metadata: Path,
    signature: dict[str, Any],
    output_dir: Path | None,
) -> bool:
    if not result.is_file() or result.stat().st_size == 0 or not metadata.is_file():
        return False
    if output_dir is not None and not output_dir.is_dir():
        return False
    try:
        recorded = json.loads(metadata.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return recorded.get("status") == "success" and recorded.get("signature") == signature


def update_analysis_report(
    case_results: Path,
    image: Path | None,
    result: Path,
    plugin: str,
) -> Path | None:
    if image is None:
        return None

    report = case_results / f"{safe_name(image.stem)}-analysis.md"
    if report.exists():
        content = report.read_text(encoding="utf-8")
    else:
        content = (
            f"# Memory Analysis: {image.name}\n\n"
            f"- Image: `{image}`\n"
            "- Status: In progress\n\n"
            "## Evidence Inventory\n\n"
            f"{EVIDENCE_START}\n"
            f"{EVIDENCE_END}\n\n"
            "## Findings\n\n"
            "Pending analyst review.\n\n"
            "## Uncertainty\n\n"
            "Pending analyst review.\n\n"
            "## Next Steps\n\n"
            "Pending analyst review.\n"
        )

    evidence = f"- `{result.name}`: `{plugin}`"
    if evidence not in content:
        if EVIDENCE_END not in content:
            content = (
                content.rstrip()
                + "\n\n## Evidence Inventory\n\n"
                + f"{EVIDENCE_START}\n{EVIDENCE_END}\n"
            )
        content = content.replace(EVIDENCE_END, f"{evidence}\n{EVIDENCE_END}", 1)
        report.write_text(content, encoding="utf-8")
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run Volatility3 with an explicit workspace cache and symbol root. "
            "Arguments after PLUGIN are passed to the plugin."
        )
    )
    parser.add_argument("--workspace", required=True, help="Investigation workspace root.")
    parser.add_argument(
        "--vol",
        help="Volatility entrypoint. Defaults to <workspace>/.venv/bin/vol, vol, or vol.py.",
    )
    parser.add_argument("--image", help="Memory image path, absolute or workspace-relative.")
    parser.add_argument("--renderer", help="Optional Volatility renderer, such as csv.")
    parser.add_argument(
        "--output-dir",
        help=(
            "Optional plugin artifact subdirectory inside the kernel result directory. "
            "Use a relative name such as dumped-files."
        ),
    )
    parser.add_argument(
        "--fresh-cache",
        action="store_true",
        help="Use .cache/volatility3-fresh for symbol-cache diagnostics.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the exact command without executing it.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Ignore a reusable result and execute the plugin again.",
    )
    parser.add_argument("plugin", help="Volatility plugin, such as linux.pslist.PsList.")
    parser.add_argument("plugin_args", nargs=argparse.REMAINDER)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    workspace = Path(args.workspace).expanduser().resolve()
    symbols = workspace / "symbols"
    results = workspace / "results"
    cache_name = "volatility3-fresh" if args.fresh_cache else "volatility3"
    cache = workspace / ".cache" / cache_name

    (symbols / "linux").mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    results.mkdir(parents=True, exist_ok=True)

    volatility = resolve_volatility(workspace, args.vol)
    command = [
        str(volatility),
        "--cache-path",
        str(cache),
        "-s",
        str(symbols),
    ]

    if args.renderer:
        command.extend(["-r", args.renderer])
    image: Path | None = None
    if args.image:
        image = workspace_path(workspace, args.image)
        if not image.is_file():
            raise FileNotFoundError(f"Memory image not found: {image}")
        command.extend(["-f", str(image)])

    case_results = case_directory(results, image)
    case_results.mkdir(parents=True, exist_ok=True)

    output_dir: Path | None = None
    if args.output_dir:
        requested_output = Path(args.output_dir).expanduser()
        if requested_output.is_absolute() or ".." in requested_output.parts:
            raise ValueError("--output-dir must be a relative subdirectory name")
        if requested_output.parts and requested_output.parts[0] == "results":
            requested_output = Path(*requested_output.parts[1:])
        output_dir = (case_results / requested_output).resolve()
        if not output_dir.is_relative_to(case_results):
            raise ValueError(
                f"Output directory must be under kernel results: {case_results}"
            )
        command.extend(["-o", str(output_dir)])

    command.append(args.plugin)
    command.extend(args.plugin_args)

    result, metadata = result_paths(
        case_results, image, args.plugin, args.plugin_args, args.renderer
    )
    signature = {
        "schema": 1,
        "volatility": file_identity(volatility),
        "image": file_identity(image) if image else None,
        "symbols": symbol_identity(symbols),
        "plugin": args.plugin,
        "plugin_args": args.plugin_args,
        "renderer": args.renderer,
        "output_dir": str(output_dir or ""),
        "fresh_cache": args.fresh_cache,
    }

    rendered_command = shlex.join(command)
    if args.dry_run:
        print(rendered_command)
        print(f"# Result: {result}")
        return 0

    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)

    if not args.force and reusable_result(result, metadata, signature, output_dir):
        print(f"Reusing result: {result}", file=sys.stderr)
        report = update_analysis_report(case_results, image, result, args.plugin)
        if report:
            print(f"Analysis document: {report}", file=sys.stderr)
        with result.open("r", encoding="utf-8", errors="replace") as handle:
            shutil.copyfileobj(handle, sys.stdout)
        return 0

    print(rendered_command, file=sys.stderr)
    print(f"Saving result: {result}", file=sys.stderr)

    temporary = result.with_name(result.name + ".part")
    failed = result.with_name(result.stem + ".failed" + result.suffix)
    failed_metadata = failed.with_name(failed.name + ".meta.json")
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert process.stdout is not None
    with temporary.open("w", encoding="utf-8") as output:
        for line in process.stdout:
            output.write(line)
            output.flush()
            sys.stdout.write(line)
            sys.stdout.flush()
    return_code = process.wait()

    record = {
        "status": "success" if return_code == 0 else "failed",
        "return_code": return_code,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "command": command,
        "result": str(result if return_code == 0 else failed),
        "signature": signature,
    }
    metadata_payload = json.dumps(record, indent=2, ensure_ascii=True) + "\n"

    if return_code == 0:
        temporary.replace(result)
        metadata_temporary = metadata.with_name(metadata.name + ".part")
        metadata_temporary.write_text(metadata_payload, encoding="utf-8")
        metadata_temporary.replace(metadata)
        if failed.exists():
            failed.unlink()
        if failed_metadata.exists():
            failed_metadata.unlink()
        if image is not None and args.plugin in ("banners.Banners", "windows.info.Info"):
            result_text = result.read_text(encoding="utf-8", errors="replace")
            if args.plugin == "banners.Banners":
                release = kernel_from_banner_text(result_text)
            else:
                release = windows_kernel_from_info_text(result_text)
            if release:
                case_results = register_kernel(results, image, release)
                result = case_results / result.name
                metadata = case_results / metadata.name
                print(f"Kernel result directory: {case_results}", file=sys.stderr)
        report = update_analysis_report(case_results, image, result, args.plugin)
        if report:
            print(f"Analysis document: {report}", file=sys.stderr)
    else:
        temporary.replace(failed)
        failed_metadata.write_text(metadata_payload, encoding="utf-8")
        print(f"Plugin failed; partial output saved: {failed}", file=sys.stderr)

    return return_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(2)
