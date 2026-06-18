# Investigation Workflows

## Unknown Image Triage

1. If no image path is supplied, inspect `images/` and select the only plausible image or ask the user to choose.
2. Run `banners` and/or `windows.info` based on the suspected OS.
3. Resolve symbols if Volatility3 cannot construct required layers.
4. Establish baseline processes and network state.
5. Ask what is abnormal for the host role before labeling activity malicious.

## Suspicious Process

1. Enumerate processes with list and scan views.
2. Compare missing, duplicated, exited, or oddly named processes.
3. Inspect ancestry with tree output.
4. For candidate PIDs, collect command line, open files/handles, loaded modules/maps, user/SID, and network endpoints.
5. Use injection plugins only after a candidate exists.

## Network Investigation

1. List sockets or endpoints with the platform's supported plugin. For Linux Volatility 3 2.28, prefer `linux.sockstat.Sockstat`; use `linux.sockscan.Sockscan` as a scan-based cross-check.
2. Resolve owning process and command line.
3. Correlate remote address, port, process path, parent, user, and open files.
4. Prioritize listening services, external established connections, and processes with no normal network role.

## Linux Rootkit Checks

1. Confirm exact kernel banner and symbols.
2. Compare `linux.pslist` with `linux.psscan`.
3. Compare `linux.lsmod.Lsmod`, `linux.malware.check_modules.Check_modules`, `linux.malware.hidden_modules.Hidden_modules`, and `linux.malware.modxview.Modxview`.
4. Run `linux.malware.check_syscall.Check_syscall` and `linux.malware.check_idt.Check_idt` only when symbols are trusted.
5. Use `linux.malware.keyboard_notifiers.Keyboard_notifiers` and `linux.malware.tty_check.Tty_Check` for hook/tampering suspicion.

## Persistence and Operator Activity

- Windows: inspect services, registry run keys, scheduled-task artifacts when plugins support them, process command lines, handles, and network endpoints.
- Linux: inspect shell history, process command lines when available, open files, mounts, service-related paths, and suspicious deleted executables.

## Reporting

Keep conclusions tied to plugin evidence:

- `High confidence`: supported by multiple consistent artifacts.
- `Medium confidence`: one strong artifact plus plausible context.
- `Low confidence`: plugin anomaly, symbol issue, or single weak indicator needing validation.

Only write files when export is explicitly requested. Use `results/` by default for exported plugin output, dumps, timelines, and reports.
