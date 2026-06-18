# Volatility3 Plugin Reference

Use this as a decision aid, not a checklist. Pick plugins that answer the current question.

## Discovery

- `banners.Banners`: Find Linux/macOS kernel banners in the image. Use first for unknown Unix-like dumps and for symbol matching.
- `windows.info.Info`: Identify Windows kernel, layer, symbol state, and basic image metadata. Use first for known or suspected Windows dumps.
- `isfinfo.IsfInfo`: Inspect available local ISF symbol files. Use when checking whether symbols are already installed.

## Linux

- `linux.pslist.PsList`: Active processes from task lists. Good first process view; misses hidden/unlinked tasks.
- `linux.psscan.PsScan`: Scans memory for process structures. Use to find terminated or hidden processes and compare with `pslist`.
- `linux.pstree.PsTree`: Parent-child relationships. Use after process enumeration to find odd ancestry.
- `linux.psaux.PsAux`: Reconstruct process arguments. Use to identify generic names such as `MainThread`, `node`, or truncated process names.
- `linux.proc.Maps`: Process memory maps. Use for injected mappings, deleted files, suspicious executable mappings, or process-specific triage.
- `linux.lsof.Lsof`: Open files per process. Use to connect processes to files, sockets, pipes, and deleted artifacts.
- `linux.sockstat.Sockstat`: Enumerate sockets with process ownership. Use for active network triage.
- `linux.sockscan.Sockscan`: Scan for socket structures that may be unlinked or no longer visible through normal ownership views. Correlate with `Sockstat`.
- `linux.bash.Bash`: Bash history recovered from process memory. Use for interactive command evidence; absence is not proof of no shell use.
- `linux.mountinfo.MountInfo`: Mounted filesystems. Use to understand containers, unusual mounts, or hidden storage.
- `linux.lsmod.Lsmod`: Loaded kernel modules from module lists. Good baseline module view.
- `linux.malware.check_modules.Check_modules`: Modules inconsistent with normal module views. Verify findings with `linux.malware.modxview.Modxview`.
- `linux.malware.hidden_modules.Hidden_modules`: Scan for potentially hidden modules.
- `linux.malware.check_syscall.Check_syscall`: Syscall table inspection. Use only after symbol resolution is reliable.
- `linux.malware.check_idt.Check_idt`: Inspect IDT handlers for unexpected targets.
- `linux.malware.keyboard_notifiers.Keyboard_notifiers`: Keyboard notifier hooks. Use for keylogger/rootkit suspicion.
- `linux.malware.tty_check.Tty_Check`: TTY receive-handler checks. Use when investigating interactive access or rootkits.

## Windows

- `windows.pslist`: Active processes from linked lists. Baseline process enumeration.
- `windows.psscan`: Pool scan for process objects. Compare with `pslist` for hidden or exited processes.
- `windows.pstree`: Process ancestry. Use to spot odd parents, service spawn chains, or LOLBin execution.
- `windows.cmdline`: Process command lines. Use after identifying candidate PIDs.
- `windows.dlllist`: Loaded DLLs. Use for suspicious module paths or process-specific context.
- `windows.handles`: Open handles. Use for files, registry keys, mutexes, and process relationships.
- `windows.netscan`: Network endpoints. Correlate remote addresses to processes and command lines.
- `windows.malfind`: VAD regions with suspicious protections/content. Use after narrowing processes; review output before claiming injection.
- `windows.vadinfo`: Detailed VAD metadata. Use to validate `malfind` and inspect memory regions.
- `windows.svcscan`: Services. Use for persistence and service-backed malware.
- `windows.registry.*`: Registry hives, keys, and values. Use for persistence, user activity, and configuration.
- `windows.hashdump`: Local account hashes when hives are recoverable. Use only when credential extraction is in scope.
- `windows.getsids`: Process SIDs. Use to understand privilege context.

## macOS

- `banners`: Use for kernel version discovery and symbol matching.
- `mac.pslist`, `mac.pstree`: Process views when symbols are available.
- `mac.netstat`: Network evidence when supported by the image and symbols.

macOS ISF reliability varies by version. Treat symbol mismatch and plugin failures as evidence quality issues before drawing conclusions.

## Selection Rules

- Process anomaly: start with `pslist`, then `psscan`, then `pstree`, then process-specific metadata.
- Network activity: start with `linux.sockstat.Sockstat`; add `linux.sockscan.Sockscan` when hidden, stale, or ownerless sockets are relevant. Then map PID to process tree, arguments, files, and memory maps.
- Rootkit suspicion: verify symbols, then compare list-vs-scan views, module checks, syscall checks, and notifier/TTY hooks.
- Injection suspicion: narrow candidate process first; use memory map/VAD plugins before dumping or scanning large ranges.
- Timeline: combine process creation, network, shell/history, registry, and file/mount evidence; do not rely on one plugin.
