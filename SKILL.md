---
name: vol3-memory-analysis
description: Volatility3 memory forensics workflows for Linux, Windows, and macOS memory images. Use when Codex needs to analyze RAM dumps with vol.py, select Volatility3 plugins deliberately, explain plugin intent, correlate plugin results, resolve missing Linux/macOS/Windows symbols, download ISF files from Abyss-W4tcher/volatility3-symbols, or generate Debian snapshot commands for exporting symbols from modern Debian-family kernels.
---

# Vol3 Memory Analysis

## Core Workflow

Treat every plugin call as a hypothesis test. Before running a plugin, state:

- The question it answers.
- The evidence expected.
- How its result changes the next command.

Do not run broad plugin lists without a reason. Start with low-cost environment discovery, then branch by operating system and user goal.

1. Determine and retain two separate absolute paths: `<skill-dir>` is the installed skill containing this file; `<workspace-root>` is the investigation directory containing `images/`, `results/`, and `symbols/`. Never treat the installed skill directory as the workspace unless the user explicitly does so.
2. Initialize the workspace with `python3 <skill-dir>/scripts/init_workspace.py --root <workspace-root>`.
3. Confirm the Volatility3 entrypoint (`vol`, `vol.py`, or `python3 vol.py`).
4. Prefer the bundled runner for every Volatility invocation:

   ```bash
   python3 <skill-dir>/scripts/run_vol3.py \
     --workspace <workspace-root> \
     --image images/<dump> \
     <plugin>
   ```

   The runner automatically injects the absolute workspace cache and `-s <workspace-root>/symbols`, saves stdout and metadata under `<workspace-root>/results/<kernel-release>/`, and reuses a successful compatible result. Use a direct Volatility command only when the runner cannot express a required option; direct commands must include the same absolute paths and save output in the same kernel directory. Do not assume Volatility automatically searches a workspace-local `symbols/` directory.
5. If the user does not provide an image path, look under `<workspace-root>/images/`. If exactly one plausible image exists, use it; if multiple exist, ask which one to analyze.
6. Identify the image with the command prefix: run `banners.Banners` for Linux/macOS candidates or `windows.info.Info` when Windows is known or strongly suspected.
7. Before the first symbol-dependent Linux plugin, verify that `<workspace-root>/symbols/linux/` contains an ISF and run `isfinfo.IsfInfo` through the runner with the target `--image`, even though the plugin does not require an image. This keeps its output in the same kernel case directory. Resolve or generate symbols only when no matching local ISF exists.
8. Before scheduling any plugin, identify the image's kernel result directory and inspect `<workspace-root>/results/<kernel-release>/` for its existing output and `.meta.json`. Reuse it when the runner reports that the result is compatible; execute with `--force` only when fresh evidence is explicitly needed.
9. Pick the next plugin from the investigation goal, not from habit.
10. Correlate at least two independent views before making a high-confidence claim, such as `linux.pslist.PsList` plus `linux.psscan.PsScan`, or `linux.sockstat.Sockstat` plus process metadata.
11. Write or update `<workspace-root>/results/<kernel-release>/<image-basename>-analysis.md` for the investigation. The document must cite the result filenames used, distinguish facts from inferences, and record unresolved questions.
12. Report facts, inferences, uncertainty, and exact follow-up commands separately.

For Debian-family symbol generation, do not assume the analysis host is the same machine as the memory image. Treat `uname -r` as evidence only when it is explicitly from the target host or recovered from the image. If symbol generation requires Debian debug packages, prefer generating a reproducible download/build script. Execute it only when the user asks to run it or confirms the analysis host is the intended build host.

## Workspace Conventions

- Run `scripts/init_workspace.py` once at the start of each new workspace. It is idempotent and must not delete or overwrite existing evidence or results.
- Treat `images/` as the default input directory for memory images.
- Resolve workspace paths to absolute paths before running Volatility. Every generated Volatility command must include both the explicit workspace cache and symbol root.
- Prefer `scripts/run_vol3.py` so cache and symbol arguments cannot be omitted. Use `--dry-run` when the exact generated command should be reviewed before execution.
- Persist every plugin's stdout under `results/<kernel-release>/`; this is the default, not an opt-in export.
- Check existing result files before running a plugin. Never rerun merely because the current conversation has not seen the earlier output.
- The runner may reuse a result only when its metadata matches the plugin, arguments, renderer, image identity, Volatility entrypoint, and symbol inventory. Use `--force` to bypass reuse.
- Use the exact Linux kernel release from the dominant image banner, for example `results/6.12.90+deb13.1-amd64/`. For Windows, derive a readable identifier from `windows.info.Info`, for example `results/windows-10.0.26100-server/`. Keep the Windows PDB GUID/Age in symbol metadata, not as the user-facing result directory. Do not use the analysis host's `uname -r`.
- If the kernel is not known yet, allow only temporary output under `results/_unidentified-kernel/<image-basename>/`. A successful `banners.Banners` or `windows.info.Info` result must classify and move that output into the kernel directory.
- Put plugin-created files, dumped files, symbol-build scripts, timelines, metadata, and generated reports under the matching kernel directory.
- Maintain the analysis document at `results/<kernel-release>/<image-basename>-analysis.md`; update it as evidence is added instead of creating disconnected summaries.
- Keep terminal summaries concise even when exporting full output to `results/`.

## References

Load only the reference needed for the current task:

- Read `references/plugins.md` when choosing or explaining Volatility3 plugins.
- Read `references/workflows.md` when the user asks for an investigation such as suspicious process triage, rootkit checks, network activity, persistence, credentials, or timeline building.
- Read `references/symbols.md` when symbols are missing, the kernel banner must be matched, or a Debian-family kernel needs an ISF generated.

## Symbol Helpers

Use bundled scripts when symbol lookup or Debian command generation is needed:

```bash
python3 scripts/resolve_vol3_symbol.py \
  --banner 'Linux version ...' \
  --symbols-dir /path/to/volatility3/volatility3/symbols/linux
```

```bash
python3 scripts/debian_snapshot_symbol_cmd.py \
  --uname-release 6.12.90+deb13.1-amd64 \
  --package-revision 6.12.90-2 \
  --arch amd64 \
  --symbols-dir ./symbols/linux \
  --script-out ./results/6.12.90+deb13.1-amd64/build-debian-6.12.90-symbol.sh
```

The Debian helper prints commands or writes a shell script. It should not be treated as permission to install packages or edit the live system. The generated script downloads a Debian snapshot debug package, downloads the prebuilt `dwarf2json` binary, extracts the debug package, and creates a `.json.xz` ISF under the requested symbols directory.

## Translation Layer Failures

When a Linux plugin reports an unsatisfied `kernel.layer_name`, `kernel.symbol_table_name`, or translation-layer requirement:

1. Inspect the exact command first. If `-s <absolute-workspace>/symbols` is absent or points to `symbols/linux`, correct it and retry before downloading or rebuilding symbols.
2. Confirm the image path and symbols path belong to the same workspace.
3. Run `banners.Banners` and `isfinfo.IsfInfo` with the same command prefix.
4. If an exact local ISF exists but is not listed or its banner does not match, diagnose ISF placement/content or cache state. Do not claim that the filename alone proves compatibility.
5. Download or generate a new ISF only after the explicit-path retry and local ISF verification fail.

## Output Standard

For analysis results, include:

- `Purpose`: why the plugin or command was selected.
- `Command`: the exact command to run, with paths filled in.
- `Observed`: concise result summary.
- `Interpretation`: what the result suggests and what it does not prove.
- `Next`: the next command or stopping condition.

When proposing external downloads, include the source URL and why it matches the memory image.
