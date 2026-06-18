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

1. Initialize the workspace by running `python3 <skill-dir>/scripts/init_workspace.py --root <workspace-root>`. This must create `images/`, `results/`, `symbols/`, and `symbols/linux/` before resolving paths or writing artifacts.
2. Confirm the Volatility3 entrypoint (`vol`, `vol.py`, or `python3 vol.py`).
3. If the user does not provide an image path, look for memory images under `images/` first. If exactly one plausible image exists there, use it; if multiple plausible images exist, list them and ask which one to analyze.
4. Identify the image: run `banners` for Linux/macOS candidates or `windows.info` when Windows is known or strongly suspected.
5. Resolve symbols before deep analysis when Volatility3 reports missing automagic/symbol failures.
6. Pick the next plugin from the investigation goal, not from habit.
7. Correlate at least two independent views before making a high-confidence claim, such as `linux.pslist.PsList` plus `linux.psscan.PsScan`, or `linux.sockstat.Sockstat` plus process metadata.
8. Report facts, inferences, uncertainty, and exact follow-up commands separately.

For Debian-family symbol generation, do not assume the analysis host is the same machine as the memory image. Treat `uname -r` as evidence only when it is explicitly from the target host or recovered from the image. If symbol generation requires Debian debug packages, prefer generating a reproducible download/build script. Execute it only when the user asks to run it or confirms the analysis host is the intended build host.

## Workspace Conventions

- Run `scripts/init_workspace.py` once at the start of each new workspace. It is idempotent and must not delete or overwrite existing evidence or results.
- Treat `images/` as the default input directory for memory images.
- Do not export plugin output files unless the user explicitly asks for export, dumping, saving, or report artifacts.
- When export is requested and no output path is provided, create/use `results/` as the default output directory.
- Put raw plugin exports, dumped files, timelines, and generated reports under `results/` with descriptive names that include the image basename and plugin or artifact type.
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
  --script-out ./results/build-debian-6.12.90-symbol.sh
```

The Debian helper prints commands or writes a shell script. It should not be treated as permission to install packages or edit the live system. The generated script downloads a Debian snapshot debug package, downloads the prebuilt `dwarf2json` binary, extracts the debug package, and creates a `.json.xz` ISF under the requested symbols directory.

## Output Standard

For analysis results, include:

- `Purpose`: why the plugin or command was selected.
- `Command`: the exact command to run, with paths filled in.
- `Observed`: concise result summary.
- `Interpretation`: what the result suggests and what it does not prove.
- `Next`: the next command or stopping condition.

When proposing external downloads, include the source URL and why it matches the memory image.
