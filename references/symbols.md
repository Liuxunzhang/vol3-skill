# Volatility3 Symbols

## Mandatory Symbol Path

Never rely on Volatility to discover a workspace-local symbol directory implicitly. Resolve the workspace root and pass the symbol root explicitly on every invocation:

```bash
python3 <skill-dir>/scripts/run_vol3.py \
  --workspace <workspace> \
  --image images/dump.raw \
  banners.Banners
```

The runner injects `--cache-path <workspace>/.cache/volatility3` and `-s <workspace>/symbols` using absolute paths. For a direct Volatility call, use the same symbol root, not `<workspace>/symbols/linux`.

## Existing ISF Lookup

For Linux and macOS, start with the kernel banner using the mandatory command prefix:

```bash
<vol> --cache-path <workspace>/.cache/volatility3 \
  -s <workspace>/symbols \
  -r pretty \
  -f <workspace>/images/sample.bin \
  banners.Banners
```

Then use `scripts/resolve_vol3_symbol.py` to query the public ISF banner mapping from `Abyss-W4tcher/volatility3-symbols` and print an install command. That repository stores common compressed ISF files and documents placing `.json.xz` files in:

```text
<volatility3_installation>/volatility3/symbols/linux/
```

Volatility3 can also query the remote ISF index directly:

```bash
<vol> \
  --cache-path <workspace>/.cache/volatility3 \
  -s <workspace>/symbols \
  --remote-isf-url 'https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners.json' \
  -f <workspace>/images/<memory_dump> \
  <plugin>
```

Use local downloads for repeatable investigations or offline work.

If the exact symbol filename is known, resolve or download it directly:

```bash
python3 scripts/resolve_vol3_symbol.py \
  --filename 'KaliLinux_6.9.11-rt-amd64_6.9.11-1kali1_amd64.json.xz' \
  --symbols-dir /path/to/volatility3/volatility3/symbols/linux \
  --download
```

The helper infers common repository paths from filenames like `Distro_kernelRelease_packageVersion_arch.json.xz`, for example `KaliLinux/amd64/6.9.11/`. If inference fails, pass `--search-root`, such as `KaliLinux/amd64/6.9.11`.

## Debian-Family New Kernels

When the public ISF mapping has no match, generate an ISF from Debian debug packages:

1. Prefer the exact `uname -r` value from the host or memory evidence, such as `6.12.90+deb13.1-amd64`.
2. If only the Debian package release is known, use `--kernel-release`, such as `6.1.0-18-amd64`.
3. Determine package revision, such as `6.1.76-1`, from the banner, package metadata, host records, or Debian package search. Do not rely only on the `+debN.M` localversion if the banner gives a clearer value. Example: banner text `Debian 6.12.90-2` means pass `--package-revision 6.12.90-2` for `6.12.90+deb13.1-amd64`.
4. Run `scripts/debian_snapshot_symbol_cmd.py` with release, arch, and symbols directory.
5. Prefer `--script-out` so the user gets a reusable, auditable script. Execute the script only after the user asks you to run it or confirms the current host is the intended build host.

The script searches `snapshot.debian.org` for `linux-image-<release>-dbgsym` and `linux-image-<release>-dbg`. It must use an actual snapshot URL discovered from the site, not a guessed timestamp. Some Debian security builds publish `-dbg` packages, not `-dbgsym`; try both.

Example with raw `uname -r`:

```bash
python3 scripts/debian_snapshot_symbol_cmd.py \
  --uname-release '6.12.90+deb13.1-amd64' \
  --package-revision '6.12.90-2' \
  --arch amd64 \
  --symbols-dir ./symbols/linux \
  --script-out ./results/6.12.90+deb13.1-amd64/build-debian-6.12.90-symbol.sh
```

Use the prebuilt `dwarf2json` binary unless the user explicitly asks to build from source:

```text
https://github.com/volatilityfoundation/dwarf2json/releases/download/v0.9.0/dwarf2json-linux-amd64
```

## Manual Export Shape

The generated command sequence should do this:

```bash
mkdir -p ./vol3-symbol-build
wget -O ./vol3-symbol-build/<package>.deb '<snapshot-url>'
wget -O ./vol3-symbol-build/tools/dwarf2json 'https://github.com/volatilityfoundation/dwarf2json/releases/download/v0.9.0/dwarf2json-linux-amd64'
chmod +x ./vol3-symbol-build/tools/dwarf2json
dpkg-deb -x ./vol3-symbol-build/<package>.deb ./vol3-symbol-build/extract
find ./vol3-symbol-build/extract -type f -name 'vmlinux-*' -print
find ./vol3-symbol-build/extract -type f -name 'System.map-*' -print
./vol3-symbol-build/tools/dwarf2json linux --elf <vmlinux-path> --system-map <System.map-path> > <isf-name>.json
xz -T0 <isf-name>.json
mkdir -p <volatility3>/volatility3/symbols/linux
cp <isf-name>.json.xz <volatility3>/volatility3/symbols/linux/
```

Do not substitute `System.map` for DWARF debug information; it is insufficient by itself. Include `--system-map` when available because Volatility3 may fail to identify the generated ISF from ELF-only output for some Debian builds.

## Lessons From Modern Debian Builds

- A kernel banner may contain both localversion and package revision. Use the package revision from the banner when present.
- `6.12.90+deb13.1-amd64` can map to a package named `linux-image-6.12.90+deb13.1-amd64-dbg` with version `6.12.90-2`; do not normalize away `.1` unless lookup fails.
- Volatility `isfinfo` may URL-encode `+` as `%2B`; this is display encoding, not a filename problem.
- Generated ISF files should be placed under the symbol root as `symbols/linux/<name>.json.xz`, and Volatility should be run with `-s symbols`, not `-s symbols/linux`.
- If the default Volatility cache is not writable, pass a workspace cache such as `--cache-path .cache/volatility3`.

## Translation Layer Diagnostic Order

An exact-looking ISF filename does not prove Volatility loaded it or that its identifying banner matches the image. For errors such as unsatisfied `kernel.layer_name` or `kernel.symbol_table_name`, use this order:

1. Retry the failed command with absolute `--cache-path` and `-s <workspace>/symbols`.
2. Confirm the file is readable under `<workspace>/symbols/linux/*.json.xz`.
3. List recognized ISFs:

   ```bash
   <vol> --cache-path <workspace>/.cache/volatility3 \
     -s <workspace>/symbols \
     -f <workspace>/images/dump.raw \
     isfinfo.IsfInfo
   ```

4. Recover the image banner with the same prefix:

   ```bash
   <vol> --cache-path <workspace>/.cache/volatility3 \
     -s <workspace>/symbols \
     -f <workspace>/images/dump.raw \
     banners.Banners
   ```

5. Compare the banner recovered from memory with the ISF identifying information. Filename equality is supporting context only.
6. If the ISF was newly copied and Volatility still does not recognize it, retry with a fresh workspace cache directory before rebuilding:

   ```bash
   <vol> --cache-path <workspace>/.cache/volatility3-fresh \
     -s <workspace>/symbols \
     -f <workspace>/images/dump.raw \
     isfinfo.IsfInfo
   ```

Only search GitHub or generate a Debian ISF after these checks show that no compatible local ISF is available.
