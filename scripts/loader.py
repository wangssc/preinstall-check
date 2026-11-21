# -*- coding: utf-8 -*-
"""只读加载 skill 包：目录或 zip。

约束：
  - 不解压到磁盘，zip 内容只在内存里读。
  - 不写、不改、不删被审对象。
  - 输出顺序完全由排序决定，与操作系统目录遍历顺序无关。
"""

from __future__ import annotations

import os
import zipfile

TEXT_CAP = 256 * 1024
ENTRY_CAP = 20000

SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "__pycache__", ".idea", ".vscode",
    "node_modules", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".tox", ".venv", "venv", "dist", "build", ".next", ".cache",
})


class Entry(object):
    """包内一个文件。"""

    __slots__ = ("path", "size", "text", "binary", "truncated", "symlink_target")

    def __init__(self, path, size, text, binary, truncated, symlink_target=None):
        self.path = path
        self.size = size
        self.text = text
        self.binary = binary
        self.truncated = truncated
        self.symlink_target = symlink_target

    @property
    def ext(self):
        base = self.path.rsplit("/", 1)[-1]
        if "." not in base[1:]:
            return ""
        return "." + base.rsplit(".", 1)[-1].lower()

    @property
    def basename(self):
        return self.path.rsplit("/", 1)[-1]

    @property
    def lines(self):
        if not self.text:
            return []
        return self.text.splitlines()


class Package(object):
    def __init__(self, name, form, entries, unsafe_entries, truncated_tree):
        self.name = name
        self.form = form
        self.entries = entries
        self.unsafe_entries = unsafe_entries
        self.truncated_tree = truncated_tree

    def find(self, suffix_or_path):
        """按相对路径精确匹配，再退化为后缀匹配。"""
        for e in self.entries:
            if e.path == suffix_or_path:
                return e
        for e in self.entries:
            if e.path.endswith("/" + suffix_or_path):
                return e
        return None

    def select(self, exts):
        return [e for e in self.entries
                if e.ext in exts and not e.binary and e.text is not None]


def _decode(raw):
    if b"\x00" in raw[:8192]:
        return None, True
    return raw.decode("utf-8", "replace"), False


def _read_file(full, size):
    try:
        with open(full, "rb") as fh:
            raw = fh.read(TEXT_CAP)
    except OSError:
        return None, False
    text, binary = _decode(raw)
    return text, binary


def load_dir(root):
    root = os.path.abspath(root)
    entries = []
    truncated = False
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            if len(entries) >= ENTRY_CAP:
                truncated = True
                break
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if os.path.islink(full):
                try:
                    target = os.readlink(full)
                except OSError:
                    target = "?"
                entries.append(Entry(rel, 0, None, False, False, target))
                continue
            try:
                size = os.path.getsize(full)
            except OSError:
                size = 0
            text, binary = _read_file(full, size)
            entries.append(Entry(rel, size, text, binary, size > TEXT_CAP))
    entries.sort(key=lambda e: e.path)
    name = os.path.basename(root.rstrip("/\\")) or "root"
    return Package(name, "dir", entries, [], truncated)


def _entry_is_unsafe(name):
    norm = name.replace("\\", "/")
    if norm.startswith("/"):
        return True
    if len(norm) > 1 and norm[1] == ":":
        return True
    parts = [p for p in norm.split("/") if p not in ("", ".")]
    return ".." in parts


def load_zip(path):
    unsafe = []
    rows = []
    truncated = False
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            raw_name = info.filename
            if raw_name.endswith("/"):
                continue
            if _entry_is_unsafe(raw_name):
                unsafe.append(raw_name)
                continue
            rows.append((raw_name.replace("\\", "/"), info))
            if len(rows) >= ENTRY_CAP:
                truncated = True
                break

        # 若整个 zip 包在单一顶层目录下，剥掉该层，让包根与目录形态对齐。
        firsts = set(p.split("/", 1)[0] for p, _ in rows)
        strip = ""
        if len(firsts) == 1:
            only = next(iter(firsts))
            if all("/" in p for p, _ in rows):
                strip = only + "/"

        entries = []
        for rel, info in rows:
            if strip:
                rel = rel[len(strip):]
            try:
                with zf.open(info) as fh:
                    raw = fh.read(TEXT_CAP)
            except (RuntimeError, zipfile.BadZipFile, OSError):
                entries.append(Entry(rel, info.file_size, None, True, True))
                continue
            text, binary = _decode(raw)
            entries.append(Entry(rel, info.file_size, text, binary,
                                 info.file_size > TEXT_CAP))

    entries.sort(key=lambda e: e.path)
    base = os.path.basename(path)
    if base.lower().endswith(".zip"):
        base = base[:-4]
    return Package(base, "zip", entries, sorted(set(unsafe)), truncated)


def load(path):
    if os.path.isdir(path):
        return load_dir(path)
    if zipfile.is_zipfile(path):
        return load_zip(path)
    raise ValueError("既不是目录也不是 zip 包：%s" % path)


# ------------------------------------------------------------ 本机已装 skill

INSTALL_ROOTS = [
    ("workbuddy", "~/.workbuddy/skills"),
    ("workbuddy-plugin", "~/.workbuddy/plugins"),
    ("claude", "~/.claude/skills"),
    ("codebuddy", "~/.codebuddy/skills"),
]

PACKAGE_CAP = 200


def _packages_in(root):
    """列出一层子目录里直接含 SKILL.md 的包；插件形态多探一层 skills/。"""
    packages = []
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return packages
    for name in names:
        path = os.path.join(root, name)
        if not os.path.isdir(path):
            continue
        if os.path.isfile(os.path.join(path, "SKILL.md")):
            packages.append(path)
            continue
        nested = os.path.join(path, "skills")
        if os.path.isdir(nested):
            try:
                subs = sorted(os.listdir(nested))
            except OSError:
                continue
            for sub in subs:
                candidate = os.path.join(nested, sub)
                if os.path.isfile(os.path.join(candidate, "SKILL.md")):
                    packages.append(candidate)
    return packages


def discover_installed(root=None):
    """探测已装 skill。只读目录名与 SKILL.md 是否存在，不读任何内容。

    返回 [(标签, 显示用根路径, [包绝对路径, ...]), ...]，顺序固定。
    """
    if root:
        shown = root
        expanded = os.path.abspath(os.path.expanduser(root))
        if not os.path.isdir(expanded):
            return []
        return [("指定目录", shown, _packages_in(expanded)[:PACKAGE_CAP])]

    found = []
    total = 0
    for label, raw in INSTALL_ROOTS:
        expanded = os.path.expanduser(raw)
        if not os.path.isdir(expanded):
            continue
        packages = _packages_in(expanded)[:max(0, PACKAGE_CAP - total)]
        if not packages:
            continue
        total += len(packages)
        found.append((label, raw, packages))
    return found
