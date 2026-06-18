# Vol3 Memory Analysis Skill

<p align="center">
  <strong>面向 Codex Agent 的 Volatility 3 内存取证工作流</strong>
</p>

<p align="center">
  精确选择插件 · 自动匹配符号 · Debian Snapshot 符号生成 · 证据关联分析
</p>

---

## 项目简介

本项目提供一个可直接由 Agent 调用的 `vol3-memory-analysis` skill，用于分析 Linux、Windows 和 macOS 内存镜像。

它不会机械地批量运行插件，而是先明确调查问题，再选择能够验证假设的插件，并通过多个独立视图交叉验证结果。对于 Linux 镜像，它还支持：

- 从 `Abyss-W4tcher/volatility3-symbols` 查找并下载常见 Volatility 3 ISF。
- 根据内核 banner 或 `uname -r` 精确识别目标内核。
- 为较新的 Debian 内核查询 `snapshot.debian.org`。
- 生成可审计、可重复执行的符号表构建脚本。
- 直接下载官方预编译 `dwarf2json`，不需要重新编译。

## 目录结构

```text
.
├── SKILL.md
├── agents/openai.yaml
├── references/
│   ├── plugins.md
│   ├── symbols.md
│   └── workflows.md
├── scripts/
│   ├── init_workspace.py
│   ├── run_vol3.py
│   ├── resolve_vol3_symbol.py
│   └── debian_snapshot_symbol_cmd.py
├── images/                 # 默认内存镜像目录，不提交 Git
├── symbols/linux/          # Linux ISF 符号目录，不提交 Git
├── results/
│   └── <kernel-release>/   # 按镜像内核分类的插件输出、元数据和分析文档
└── vol3-symbol-build/      # Debian 符号生成临时目录
```

## 初始化工作区

首次克隆仓库后，运行初始化脚本创建默认工作目录：

```bash
python3 scripts/init_workspace.py
```

也可以指定其他工作区根目录：

```bash
python3 scripts/init_workspace.py --root /path/to/workspace
```

脚本会创建：

```text
images/
results/
symbols/
symbols/linux/
```

该操作可重复执行，不会删除或覆盖已有镜像、符号和分析结果。Agent 调用 skill 开始分析时，也应先执行此初始化步骤。

## 环境准备

推荐使用 Python 虚拟环境安装 Volatility 3：

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip volatility3
```

验证环境：

```bash
.venv/bin/vol --help
```

系统还应提供以下基础命令：

```text
wget
dpkg-deb
xz
find
```

## 安装 Skill

仓库根目录就是标准 Skill 目录，因此可以直接在 Codex 中输入：

```text
给我安装这个skill到codex，https://github.com/Liuxunzhang/vol3-skill.git
```

也可以手动运行 Codex 官方安装器：

```bash
python3 ~/.codex/skills/.system/skill-installer/scripts/install-skill-from-github.py \
  --repo Liuxunzhang/vol3-skill \
  --path . \
  --name vol3-memory-analysis
```

本地开发时，可以将仓库根目录软链接到 Codex skill 目录：

```bash
mkdir -p ~/.codex/skills
ln -s "$(pwd)" ~/.codex/skills/vol3-memory-analysis
```

已经存在同名目录时，不要直接覆盖；先确认其内容和来源。

安装后需要重启 Codex，使新 Skill 被加载。

安装后可以在对话中明确调用：

```text
使用 $vol3-memory-analysis 分析 images/dump.raw
```

也可以直接描述目标：

```text
使用 vol3 memory analysis skill 检查 images/dump.raw 中的异常进程和网络连接。
```

## 基本约定

| 类型 | 默认位置 | 行为 |
|---|---|---|
| 内存镜像 | `images/` | 未提供路径时优先查找 |
| Linux 符号 | `symbols/linux/` | Volatility 使用 `-s symbols` |
| 插件结果 | `results/<内核版本>/` | 每次执行自动保存，兼容结果优先复用 |
| 分析文档 | `results/<内核版本>/<镜像名>-analysis.md` | 随调查过程持续更新 |
| Debian 构建文件 | `vol3-symbol-build/` | 保存 debug deb、解包文件和临时 ISF |
| Volatility 缓存 | `.cache/volatility3/` | 避免用户目录缓存不可写 |

这些目录默认被 `.gitignore` 排除，防止提交内存镜像、调试包、分析产物和本地环境。

## 分析内存镜像

激活虚拟环境：

```bash
source .venv/bin/activate
```

推荐通过 Skill 自带执行器调用 Volatility。它会自动注入工作区绝对 cache 路径和 `-s <workspace>/symbols`，并将插件输出与元数据保存到对应内核目录，例如 `results/6.12.90+deb13.1-amd64/`：

```bash
python3 scripts/run_vol3.py \
  --workspace . \
  --image images/dump.raw \
  linux.pslist.PsList
```

再次执行相同命令时，执行器会先校验已有结果对应的镜像、符号、Volatility、插件参数和 renderer。完全一致时直接读取已有结果，不重复扫描镜像。需要强制刷新时添加 `--force`。

只检查最终命令、不执行：

```bash
python3 scripts/run_vol3.py \
  --workspace . \
  --image images/dump.raw \
  --dry-run \
  linux.pslist.PsList
```

Linux 镜像首先获取 banner：

```bash
python3 scripts/run_vol3.py \
  --workspace . \
  --image images/dump.raw \
  banners.Banners
```

不要依赖 Volatility 自动搜索当前目录中的 `symbols/`。执行器会固定使用符号根目录 `symbols/`，而不是 `symbols/linux/`。

符号解析成功后，可以按调查目的继续：

```bash
# 活动进程
python3 scripts/run_vol3.py --workspace . --image images/dump.raw \
  linux.pslist.PsList

# 进程树
python3 scripts/run_vol3.py --workspace . --image images/dump.raw \
  linux.pstree.PsTree

# 进程参数
python3 scripts/run_vol3.py --workspace . --image images/dump.raw \
  linux.psaux.PsAux

# 活动套接字
python3 scripts/run_vol3.py --workspace . --image images/dump.raw \
  linux.sockstat.Sockstat
```

插件名称会随 Volatility 3 版本变化。应先通过以下命令确认当前环境实际支持的名称：

```bash
.venv/bin/vol --help
```

## 从 GitHub 下载现有符号表

已知完整文件名时：

```bash
python3 scripts/resolve_vol3_symbol.py \
  --filename 'KaliLinux_6.9.11-rt-amd64_6.9.11-1kali1_amd64.json.xz' \
  --symbols-dir ./symbols/linux \
  --download
```

根据完整 kernel banner 查找：

```bash
python3 scripts/resolve_vol3_symbol.py \
  --banner 'Linux version ...' \
  --symbols-dir ./symbols/linux
```

不添加 `--download` 时，脚本只输出真实下载命令，不修改符号目录。

符号来源：

```text
https://github.com/Abyss-W4tcher/volatility3-symbols
```

## 生成 Debian 新内核符号

当 GitHub 仓库没有精确匹配时，需要使用 Debian debug 包生成 ISF。

首先从内存 banner 中确认两个值：

```text
Kernel release:   6.12.90+deb13.1-amd64
Package revision: 6.12.90-2
```

注意：`+deb13.1` 不能可靠推导出 Debian 包版本。只要 banner 中存在 `Debian 6.12.90-2`，就应显式传入 `--package-revision 6.12.90-2`。

生成构建脚本：

```bash
python3 scripts/debian_snapshot_symbol_cmd.py \
  --uname-release '6.12.90+deb13.1-amd64' \
  --package-revision '6.12.90-2' \
  --arch amd64 \
  --symbols-dir ./symbols/linux \
  --script-out ./results/6.12.90+deb13.1-amd64/build-debian-6.12.90-symbol.sh
```

该命令会查询 Debian Snapshot 并生成脚本，但不会自动安装内核包，也不会修改运行中的内核。

审核脚本后执行：

```bash
bash results/6.12.90+deb13.1-amd64/build-debian-6.12.90-symbol.sh
```

生成脚本将执行以下操作：

1. 从 `snapshot.debian.org` 下载精确版本的 `-dbg` 或 `-dbgsym` 包。
2. 下载 `dwarf2json v0.9.0` 官方预编译二进制。
3. 使用 `dpkg-deb -x` 解包，不向系统安装软件包。
4. 查找匹配的 `vmlinux` 和 `System.map`。
5. 通过 `dwarf2json linux --elf ... --system-map ...` 生成 ISF。
6. 压缩并复制到 `symbols/linux/`。

默认 dwarf2json 地址：

```text
https://github.com/volatilityfoundation/dwarf2json/releases/download/v0.9.0/dwarf2json-linux-amd64
```

## 验证符号表

```bash
python3 scripts/run_vol3.py \
  --workspace . \
  --image images/dump.raw \
  isfinfo.IsfInfo
```

随后运行一个基础插件验证符号和镜像是否匹配：

```bash
python3 scripts/run_vol3.py \
  --workspace . \
  --image images/dump.raw \
  linux.pslist.PsList
```

`isfinfo` 中将文件名的 `+` 显示为 `%2B` 属于 URL 编码，不代表文件名错误。

## 调查工作流

### 异常进程

```text
PsList -> PsScan -> PsTree -> PsAux -> Maps/Lsof -> Sockstat
```

先比较链表和扫描视图，再检查父子关系、完整命令行、内存映射、文件和网络，不应仅凭进程名称下结论。

### 网络活动

```text
Sockstat -> Sockscan -> PsAux -> PsTree -> Lsof
```

重点关注外部已建立连接、异常监听端口、无合理网络职责的进程，以及连接与命令行不一致的情况。

### Linux Rootkit

```text
PsList/PsScan
Lsmod/Check_modules/Hidden_modules/Modxview
Check_syscall/Check_idt
Keyboard_notifiers/Tty_Check
```

Rootkit 检查高度依赖精确符号。符号未验证时，插件异常只能作为低置信度线索。

## 结果复用与分析文档

执行器默认将插件标准输出写入 `results/<kernel-release>/`，同时保留终端输出。例如：

```bash
python3 scripts/run_vol3.py \
  --workspace . \
  --image images/dump.raw \
  linux.pslist.PsList
```

典型产物：

```text
results/6.12.90+deb13.1-amd64/dump-linux.pslist.PsList.txt
results/6.12.90+deb13.1-amd64/dump-linux.pslist.PsList.txt.meta.json
results/6.12.90+deb13.1-amd64/dump-analysis.md
```

执行器从 Linux 镜像 banner 提取内核 release；Windows 镜像则从 `windows.info.Info` 提取 NT 版本、build 和产品类型，例如 `results/windows-10.0.26100-server/`。Windows PDB GUID/Age 只用于精确匹配符号，不再作为面向用户的结果目录名。映射保存在 `results/.vol3-cases.json`；系统版本尚未获得时，结果暂存在 `results/_unidentified-kernel/<镜像名>/`，识别成功后自动迁移到正式目录。

元数据用于判断结果是否仍与当前镜像、符号和命令匹配。Agent 后续分析必须先读取对应内核目录，只有不存在兼容结果时才执行插件。失败输出会保留为 `*.failed.*`，但不会作为成功缓存复用。

首次成功执行镜像插件时，执行器还会创建 `results/<内核版本>/<镜像名>-analysis.md`，并维护其中的证据文件清单。Agent 负责继续填写和更新 Findings、Uncertainty、Next Steps 等分析内容。

使用其他 renderer 时：

```bash
python3 scripts/run_vol3.py \
  --workspace . \
  --image images/dump.raw \
  --renderer csv \
  linux.pslist.PsList
```

插件自身需要导出文件时，使用相对目录，例如 `--output-dir dumped-files`，执行器会将其放到当前内核结果目录。最终分析结论写入并持续更新 `results/<内核版本>/<镜像名>-analysis.md`，其中应注明引用的插件结果文件、事实、推断、置信度和待确认事项。

## 常见问题

### Volatility 找不到符号

- 确认符号位于 `symbols/linux/*.json.xz`。
- 每条 Volatility 命令都必须显式包含绝对路径 `-s "$WORKSPACE_ROOT/symbols"`。
- 参数指向符号根目录，不能使用 `-s "$WORKSPACE_ROOT/symbols/linux"`。
- 用 `isfinfo.IsfInfo` 检查 banner identifying information。
- 确认 ISF 是通过匹配的 `vmlinux` 生成。

### `pslist` 提示 translation layer 未建立

不要立即重新下载或生成符号。按以下顺序检查：

```bash
python3 scripts/run_vol3.py \
  --workspace . \
  --image images/dump.raw \
  isfinfo.IsfInfo

python3 scripts/run_vol3.py \
  --workspace . \
  --image images/dump.raw \
  banners.Banners

python3 scripts/run_vol3.py \
  --workspace . \
  --image images/dump.raw \
  linux.pslist.PsList
```

如果本地存在 `Debian_6.12.90+deb13.1-amd64_6.12.90-2_amd64.json.xz`，仍需确认 `isfinfo` 能加载它，并且其 identifying banner 与内存中的 banner 一致。文件名完全匹配不等于 ISF 内容必然兼容。

### ELF-only ISF 无法识别

部分 Debian 构建只传 `--elf` 时，生成的 ISF 可能缺少可匹配的 identifying banner。应同时传入：

```bash
dwarf2json linux --elf <vmlinux> --system-map <System.map>
```

### 默认缓存目录不可写

使用项目内缓存：

```bash
--cache-path .cache/volatility3
```

### `python -m volatility3` 无法运行

某些安装方式不提供 `volatility3.__main__`。直接使用虚拟环境生成的入口：

```bash
.venv/bin/vol
```

### 内存镜像无法读取

检查权限：

```bash
ls -lh images/
```

镜像通常包含敏感数据，不建议通过放宽到全局可读来解决权限问题；只授予分析账户所需的最小权限。

## 安全注意事项

- 内存镜像可能包含凭据、密钥、Token、会话内容和个人数据。
- 不要将 `images/`、`results/`、`symbols/` 或 debug 包提交到公共仓库。
- 不要因为目标镜像是 Debian，就在当前分析机上安装对应内核。
- 默认使用 `dpkg-deb -x` 离线解包 debug 包，而不是 `apt install` 或 `dpkg -i`。
- 外部 IP、进程名和插件异常都不是单独定性的充分证据。

## Skill 开发与校验

修改 skill 后运行：

```bash
python3 ~/.codex/skills/.system/skill-creator/scripts/quick_validate.py \
  .
```

Python 脚本语法检查：

```bash
python3 -m py_compile scripts/*.py
```

## 数据来源

- Volatility 3: <https://github.com/volatilityfoundation/volatility3>
- 公共 Linux ISF: <https://github.com/Abyss-W4tcher/volatility3-symbols>
- Debian Snapshot: <https://snapshot.debian.org>
- dwarf2json: <https://github.com/volatilityfoundation/dwarf2json>

---

本项目的目标是让 Agent 给出可复现、证据驱动的内存分析过程，而不是仅返回一组未经解释的插件输出。
