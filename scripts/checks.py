# -*- coding: utf-8 -*-
"""检查项集合。每条 finding 必须带 文件 + 行号 + 原文片段。

规则分七组：归档安全 / 结构 / 触发精度 / 代码风险 / 组合风险 / 价值 / 维护。
所有匹配只读内存文本，不改动被审对象。
"""

from __future__ import annotations

import ast
import re
import sys

try:  # 3.10+
    STDLIB = set(sys.stdlib_module_names)
except AttributeError:  # 3.8 / 3.9
    STDLIB = {
        "abc", "argparse", "ast", "asyncio", "base64", "binascii", "bisect",
        "calendar", "cmath", "codecs", "collections", "colorsys", "concurrent",
        "configparser", "contextlib", "copy", "csv", "ctypes", "dataclasses",
        "datetime", "decimal", "difflib", "dis", "enum", "errno", "filecmp",
        "fileinput", "fnmatch", "fractions", "ftplib", "functools", "gc",
        "getopt", "getpass", "gettext", "glob", "gzip", "hashlib", "heapq",
        "hmac", "html", "http", "imaplib", "importlib", "inspect", "io",
        "ipaddress", "itertools", "json", "keyword", "linecache", "locale",
        "logging", "lzma", "mailbox", "math", "mimetypes", "multiprocessing",
        "numbers", "operator", "os", "pathlib", "pickle", "pkgutil",
        "platform", "plistlib", "pprint", "queue", "random", "re", "readline",
        "secrets", "select", "shelve", "shlex", "shutil", "signal", "site",
        "smtplib", "socket", "sqlite3", "ssl", "stat", "statistics", "string",
        "stringprep", "struct", "subprocess", "sys", "tarfile", "tempfile",
        "textwrap", "threading", "time", "timeit", "token", "tokenize",
        "traceback", "types", "typing", "unicodedata", "unittest", "urllib",
        "uuid", "venv", "warnings", "wave", "weakref", "webbrowser", "xml",
        "xmlrpc", "zipfile", "zipimport", "zlib", "zoneinfo",
    }

CODE_EXT = frozenset({
    ".py", ".pyw", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts",
    ".rb", ".pl", ".php", ".ps1", ".bat", ".cmd",
})
DOC_EXT = frozenset({".md", ".txt", ".rst", ".yaml", ".yml", ".toml", ".json"})

SNIPPET_CAP = 160


def _snip(line):
    s = line.strip()
    if len(s) > SNIPPET_CAP:
        s = s[:SNIPPET_CAP] + "…"
    return s


def _finding(rule, dim, sev, ded, kill, entry, lineno, snippet, msg, adv, name=None):
    if name is not None:
        path = name
    elif entry is not None:
        path = entry.path
    else:
        path = "./"
    return {
        "rule": rule,
        "dim": dim,
        "sev": sev,
        "ded": ded,
        "kill": bool(kill),
        "file": path,
        "line": lineno,
        "snippet": snippet,
        "msg": msg,
        "adv": adv,
    }


def _scan(entry, rules, out):
    """对单个文件跑一组正则规则。"""
    for idx, raw in enumerate(entry.lines, start=1):
        for r in rules:
            if r["_re"].search(raw):
                out.append(_finding(r["rule"], r["dim"], r["sev"], r["ded"],
                                    r["kill"], entry, idx, _snip(raw),
                                    r["msg"], r["adv"]))


def _compile(rules):
    for r in rules:
        r["_re"] = re.compile(r["pat"])
    return rules


# ---------------------------------------------------------------- 规则表

CODE_RULES = _compile([
    dict(rule="CRED_ACCESS", dim="risk", sev="high", ded=30, kill=True,
         pat=r"(\.ssh/|id_rsa|id_ed25519|id_ecdsa|\.aws/credentials|\.netrc|"
             r"\.pgpass|\.kube/config|\.docker/config\.json|Library/Keychains|\.gnupg/)",
         msg="脚本引用本地凭证存储路径",
         adv="核实它为什么需要读这里。凭证一旦被读走无法撤销，建议不装或先全文审阅。"),
    dict(rule="DESTRUCTIVE_HARD", dim="risk", sev="high", ded=30, kill=True,
         pat=r"(rm\s+-[a-z]*rf\s+(/|~|\$HOME)|shutil\.rmtree\(\s*[\"']?(/|~)|"
             r"\bmkfs\b|\bdd\s+if=|\bformat\s+[a-zA-Z]:)",
         msg="命中破坏性删除或格式化命令",
         adv="建议不要安装。如需使用，先在隔离环境里看清它删的是什么路径。"),
    dict(rule="WRITE_OUTSIDE", dim="risk", sev="high", ded=12, kill=False,
         pat=r"(open\(\s*[\"']/(etc|usr|var|bin|sbin|System|Library)/|"
             r"Path\(\s*[\"']/(etc|usr|var|bin|sbin|System|Library)/)",
         msg="向系统目录写入",
         adv="核实它写什么、是否有回滚方式。系统目录写入通常超出 skill 的职责。"),
    dict(rule="HARDCODED_TOKEN", dim="risk", sev="high", ded=14, kill=False,
         pat=r"(sk-[A-Za-z0-9_\-]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|"
             r"xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
             r"Bearer\s+[A-Za-z0-9._\-]{24,})",
         msg="代码里出现疑似硬编码凭证",
         adv="核实这是示例串还是真凭证。真凭证应视为已泄露，且该 skill 可能调用他人额度。"),
    dict(rule="SUBPROC", dim="risk", sev="med", ded=10, kill=False,
         pat=r"(subprocess\.(run|call|Popen|check_output|check_call|getoutput)|"
             r"os\.system|os\.popen|os\.exec[lv]|commands\.getoutput)",
         msg="调起子进程执行外部命令",
         adv="核实命令内容是否固定。命令由输入拼接而成时风险显著上升。"),
    # 反序列化不是「一个库引用」级别的提示：pickle / marshal / dill 的 loads 对不受信任数据
    # 等价于把对方发来的字节当代码跑。它和 `import urllib` 同级是错的，所以给 high。
    dict(rule="PICKLE", dim="risk", sev="high", ded=14, kill=False,
         pat=r"(pickle\.loads?|marshal\.loads|dill\.loads|yaml\.load\()",
         msg="反序列化不受信任的数据",
         adv="核实数据来源。反序列化外部数据等价于执行外部代码。"),
    dict(rule="SHELL_TRUE", dim="risk", sev="med", ded=8, kill=False,
         pat=r"shell\s*=\s*True",
         msg="以 shell 解释方式执行命令",
         adv="核实拼接进命令的字符串是否包含用户输入。"),
    dict(rule="EVAL_EXEC", dim="risk", sev="med", ded=8, kill=False,
         pat=r"(?<![\w.])(eval|exec)\s*\(",
         msg="使用 eval/exec 动态执行字符串",
         adv="核实被执行的内容来自哪里。来自网络或文件时等同开后门。"),
    dict(rule="NET_CALL", dim="risk", sev="med", ded=8, kill=False,
         pat=r"(urlopen|urlretrieve|requests\.(get|post|put|patch|delete)|"
             r"httpx\.|socket\.socket|http\.client\.HTTP)",
         msg="发起网络请求",
         adv="核实目标域名与发送内容。「离线可用」是这个工具的基本前提，联网要单独看。"),
    dict(rule="CRED_MENTION", dim="risk", sev="med", ded=6, kill=False,
         pat=r"(\.env\b(?!\.example)|API_KEY|SECRET_KEY|ACCESS_TOKEN|os\.environ\[)",
         msg="读取环境变量或 .env 中的密钥",
         adv="核实它读了哪些键、是否外传。读密钥本身不等于恶意，但必须可见。"),
    dict(rule="DESTRUCTIVE_SOFT", dim="risk", sev="med", ded=6, kill=False,
         pat=r"(shutil\.rmtree|os\.remove|os\.unlink|\.unlink\(|os\.rmdir)",
         msg="包含文件删除操作",
         adv="核实删除路径是否由用户显式指定，以及是否有二次确认。"),
    dict(rule="NET_IMPORT", dim="risk", sev="low", ded=4, kill=False,
         pat=r"^\s*(import|from)\s+(requests|urllib|httpx|socket|ftplib|smtplib|aiohttp|websocket)\b",
         msg="引入网络库",
         adv="核实这个依赖是否真的被用到。未使用的网络库会扩大攻击面。"),
    dict(rule="TODO_MARK", dim="maint", sev="low", ded=2, kill=False,
         pat=r"(TODO|FIXME|XXX|HACK)\b",
         msg="残留未完成标记",
         adv="核实对应功能是否真的可用。TODO 集中处往往是没做完的主路径。"),
    dict(rule="ABS_PATH", dim="maint", sev="low", ded=2, kill=False,
         pat=r"(/Users/[A-Za-z0-9_.\-]+|/home/[A-Za-z0-9_.\-]+|[A-Za-z]:\\\\?Users\\\\?[A-Za-z0-9_.\-]+)",
         msg="写死了本机绝对路径",
         adv="核实这是文档示例还是真实默认值。真实默认值意味着换台机器就跑不起来。"),
])

IMPORT_RE = re.compile(r"^\s*(?:from\s+([A-Za-z_][\w.]*)|import\s+([A-Za-z_][\w., ]*))")
BROAD_RE = re.compile(
    r"(任何(任务|需求|问题)|所有(任务|需求)|万能|什么都能|everything|anything you|"
    r"all your|随便什么)")
WHEN_USE_RE = re.compile(r"(何时用|什么时候用|何时使用|适用场景|when to use)", re.I)
# description 里交代场景的常见写法。命中即认为「何时用」已经写在正确的位置上。
SCENE_RE = re.compile(r"(用于|适合|用来|帮你|协助|当.{0,10}时|需要.{0,8}时|"
                      r"when you|when the user|use when|helps? you)", re.I)
WHEN_NOT_RE = re.compile(r"(何时不用|什么时候不用|不适用|不要用|when not|do not use)", re.I)
OUTPUT_RE = re.compile(r"(输出格式|输出约定|产物|output format|报告格式)", re.I)
REF_RE = re.compile(r"(?:`|\(|\[)((?:scripts|references|assets|templates)/[\w./\-]+)")


# ---------------------------------------------------------------- 各检查组

def _check_archive(pkg, out):
    for name in pkg.unsafe_entries:
        out.append(_finding("UNSAFE_ZIP_ENTRY", "risk", "high", 35, True,
                            None, 0, "（zip 条目）" + name,
                            "zip 条目包含「..」或绝对路径",
                            "这类包本身就是攻击载荷，不要解压。建议直接放弃该来源。",
                            name=name))
    if pkg.truncated_tree:
        out.append(_finding("TREE_TRUNCATED", "maint", "low", 2, False,
                            None, 0, "（文件数超过 %d，已截断）" % 20000,
                            "包内文件数过多，扫描被截断",
                            "核实是否夹带了无关内容。skill 包通常不该有上万个文件。"))


def _check_structure(pkg, out):
    skill = pkg.find("SKILL.md")
    if skill is None:
        out.append(_finding("MISSING_SKILL_MD", "exec", "high", 14, False,
                            None, 0, "（包根无 SKILL.md，共 %d 个文件）" % len(pkg.entries),
                            "缺少可安装入口 SKILL.md",
                            "核实包结构。没有 SKILL.md 的包按现状装不上。"))
        return None, None, ""

    lines = skill.lines
    if not lines or lines[0].strip() != "---":
        out.append(_finding("NO_FRONTMATTER", "exec", "high", 12, False,
                            skill, 1, _snip(lines[0]) if lines else "（空文件）",
                            "SKILL.md 开头没有 YAML frontmatter",
                            "核实打包方式。缺 frontmatter 时平台读不到 name/description，无法触发。"))
        return None, None, "\n".join(lines)

    end = -1
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end = i
            break
    if end < 0:
        out.append(_finding("NO_FRONTMATTER", "exec", "med", 12, False,
                            skill, 1, _snip(lines[0]),
                            "frontmatter 没有闭合的 ---",
                            "核实文件是否被截断。"))
        return None, None, "\n".join(lines)

    meta = {}
    last_key = None
    for i in range(1, end):
        raw = lines[i]
        if not raw.strip():
            continue
        m = re.match(r"^([A-Za-z0-9_\-]+)\s*:\s*(.*)$", raw)
        if m and not raw.startswith((" ", "\t")):
            last_key = m.group(1).lower()
            meta[last_key] = m.group(2).strip().strip('"').strip("'")
        elif last_key:
            meta[last_key] = (meta[last_key] + " " + raw.strip()).strip()

    body = "\n".join(lines[end + 1:])

    if not meta.get("name"):
        out.append(_finding("FRONTMATTER_FIELD", "exec", "high", 7, False,
                            skill, 1, _snip(lines[0]) if lines else "---",
                            "frontmatter 缺少 name",
                            "核实是否手写坏了。name 缺失时无法作为 skill 注册。"))
    if not meta.get("description"):
        out.append(_finding("FRONTMATTER_FIELD", "exec", "high", 7, False,
                            skill, 1, _snip(lines[0]) if lines else "---",
                            "frontmatter 缺少 description",
                            "核实 description。它是唯一的触发依据，缺了等于装了个不会被叫醒的工具。"))

    for i in range(end + 1, len(lines)):
        for m in REF_RE.finditer(lines[i]):
            ref = m.group(1).rstrip(".,)")
            if pkg.find(ref) is None:
                out.append(_finding("BROKEN_REF", "exec", "med", 3, False,
                                    skill, i + 1, _snip(lines[i]),
                                    "正文引用了包内不存在的文件：%s" % ref,
                                    "核实引用路径。断链意味着那段说明照着做会失败。"))
    return meta, skill, body


def _check_trigger(pkg, meta, skill, body, out):
    if skill is None:
        return
    name = (meta or {}).get("name", "")
    desc = (meta or {}).get("description", "")

    if desc:
        if len(desc) < 40:
            out.append(_finding("VAGUE_DESC", "trigger", "med", 8, False,
                                skill, 1, "description: " + desc[:SNIPPET_CAP],
                                "description 过短，缺少可判定的触发条件",
                                "核实它到底什么时候该被唤醒。太短的描述会让它在该出现时不出现、不该出现时乱出现。"))
        if BROAD_RE.search(desc):
            out.append(_finding("BROAD_TRIGGER", "trigger", "med", 5, False,
                                skill, 1, "description: " + desc[:SNIPPET_CAP],
                                "description 声称适用范围过宽",
                                "核实是否真的覆盖这些场景。宽触发会抢走别的 skill 的活，且多数情况下兑现不了。"))

    if name and pkg.form == "dir":
        norm = lambda s: re.sub(r"[^a-z0-9]", "", s.lower())
        if norm(name) != norm(pkg.name):
            out.append(_finding("NAME_MISMATCH", "trigger", "low", 2, False,
                                skill, 1, "name: " + name,
                                "frontmatter 的 name 与目录名不一致（%s / %s）" % (name, pkg.name),
                                "核实是否有意为之。不一致会让安装后的路径与文档对不上。"))

    body_len = len(body.strip())
    # 阈值分档：包里有脚本时，正文短是正常的——活交给代码了，正文只需要说清怎么调。
    # 纯文字包没有别的东西可承载流程，正文就是全部内容，所以要求更高。
    scripted = bool(pkg.select(CODE_EXT))
    thin_limit = 120 if scripted else 300
    if body_len < 80:
        # 这一档不是「写得短」，是「没有内容」。正文为 0 的包不能靠扣 6 分带过：
        # 它会在总分上和真包挤进同一档，用户读完以为「核实一下就能装」。
        out.append(_finding("EMPTY_BODY", "trigger", "high", 20, False,
                            skill, 1, "（正文 %d 字）" % body_len,
                            "正文不足 80 字，等于没有内容",
                            "不要装。包里没有可执行的流程，装进来只占上下文，不如直接用一句话问模型。"))
    elif body_len < thin_limit:
        out.append(_finding("THIN_BODY", "trigger", "med", 6, False,
                            skill, 1, "（正文 %d 字，%s档阈值 %d 字）"
                            % (body_len, "有脚本" if scripted else "纯文字", thin_limit),
                            "正文过短，缺少可执行的流程说明",
                            "核实正文是否被裁掉。正文太短意味着装进来只有一句 prompt 的价值。"))
    # 「何时该用」的最佳位置是 description，不是正文：description 才是唯一的触发依据，
    # 正文要触发之后才加载。所以正文里没写不等于没写，先看 description 有没有交代场景。
    if not WHEN_USE_RE.search(body) and not SCENE_RE.search(desc):
        out.append(_finding("NO_WHEN_TO_USE", "trigger", "med", 5, False,
                            skill, 1, "（正文未出现「何时用 / 适用场景」）",
                            "正文没有写何时该用",
                            "核实触发边界。没有使用边界的 skill 只能靠猜。"))
    if not WHEN_NOT_RE.search(body):
        out.append(_finding("NO_WHEN_NOT", "trigger", "low", 3, False,
                            skill, 1, "（正文未出现「何时不用 / 不适用」）",
                            "正文没有写何时不该用",
                            "核实是否存在邻近场景被误触发。缺这一条最常见的结果是抢活。"))
    if not OUTPUT_RE.search(body):
        out.append(_finding("NO_OUTPUT_SPEC", "trigger", "low", 3, False,
                            skill, 1, "（正文未出现「输出格式 / 产物」）",
                            "正文没有约定输出形态",
                            "核实产物是否稳定。没有输出约定的 skill 每次给你不一样的东西。"))


# 规则表所在的文件本身就是一堆"危险模式"的字符串字面量。扫自己时会把这些定义
# 当成真的危险代码，出现"这个工具判自己不装"的荒谬结论。按文件内容识别规则表并跳过。
RULE_TABLE_MARK = "CODE_RULES = _compile("


def _check_code(pkg, out):
    code = pkg.select(CODE_EXT)
    for e in code:
        if RULE_TABLE_MARK in (e.text or ""):
            pass  # 规则定义文件：里面的字符串是检测模式，不是行为
        else:
            _scan(e, CODE_RULES, out)
        if e.ext in (".py", ".pyw"):
            try:
                ast.parse(e.text or "")
            except SyntaxError as exc:
                line = exc.lineno or 1
                snippet = _snip(e.lines[line - 1]) if 0 < line <= len(e.lines) else ""
                out.append(_finding("SYNTAX_ERROR", "exec", "med", 10, False,
                                    e, line, snippet,
                                    "Python 语法错误：%s" % exc.msg,
                                    "核实这个文件是否真的被使用。语法错的脚本装进来也跑不了。"))
    for e in pkg.entries:
        if e.symlink_target is not None:
            tgt = e.symlink_target
            if tgt.startswith("/") or tgt.startswith("\\") or ".." in tgt.split("/"):
                out.append(_finding("SYMLINK_ESCAPE", "risk", "high", 10, False,
                                    e, 0, "symlink -> " + tgt,
                                    "包内软链接指向包外",
                                    "核实它指向哪里。指向包外的软链接可以让脚本读到工作目录之外的文件。"))
    return code


NET_PAT = re.compile(r"(urlopen|requests\.(get|post|put)|httpx\.|socket\.socket|"
                     r"http\.client\.HTTP|urlretrieve)")
# 凭证分强弱两级。原来把 os.environ 和 .ssh/ 平级，结果是：
# 本机 4 个联网脚本全部被判死，逐条回查，命中的全是 os.environ —— 读环境变量是配置读取的
# 标准写法（端口、路径、调试开关），不是凭证读取。据此否决等于判死每一个带配置的联网工具。
CRED_STRONG = re.compile(r"(\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.netrc|"
                         r"\.kube/config|\.pypirc|\.git-credentials|\.docker/config\.json)")
# 弱特征要带密钥类的名字才算：os.environ["PORT"] 不算，os.environ["API_KEY"] 才算。
CRED_SECRET = re.compile(r"((os\.environ|getenv)[^\n]{0,60}(API_KEY|SECRET|TOKEN|PASSWORD|"
                         r"ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)|(API_KEY|SECRET|TOKEN|PASSWORD|"
                         r"ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)[^\n]{0,60}(os\.environ|getenv))")
CRED_PAT = CRED_STRONG
# 共现窗口。为什么不是「同文件」：6000 行的本地服务脚本里，
# 「读环境变量」和「开 socket」两件事几乎必然都出现，同文件共现的信息量接近 0。
# 在一个 40 行的窗口内共现，才说明这两件事真的被写在了同一段流程里。
EXFIL_WINDOW = 40


def _cred_lines(lines):
    return [i for i, raw in enumerate(lines, start=1)
            if CRED_STRONG.search(raw) or CRED_SECRET.search(raw)]


def _check_composite(pkg, out):
    code = pkg.select(CODE_EXT)
    for e in code:
        text = e.text or ""
        if RULE_TABLE_MARK in text:
            continue  # 规则定义文件：网络与凭证的模式相邻是被写在一起的，不是行为
        net_lines = [i for i, raw in enumerate(e.lines, start=1) if NET_PAT.search(raw)]
        cred_lines = _cred_lines(e.lines)
        # 取「最近的一对」，而不是「存在即命中」：距离决定这是不是同一段流程里的组合。
        best = None
        for n in net_lines:
            for c in cred_lines:
                gap = abs(n - c)
                if best is None or gap < best[0]:
                    best = (gap, min(n, c), n, c)
        if best is not None:
            gap, _, n, c = best
            if gap <= EXFIL_WINDOW:
                out.append(_finding("NET_EXFIL", "risk", "high", 28, True,
                                    e, n, _snip(e.lines[n - 1]),
                                    "第 %d 行发起网络请求，第 %d 行读取本地凭证，"
                                    "相距 %d 行（阈值 %d 行）" % (n, c, gap, EXFIL_WINDOW),
                                    "核实这段代码是否把本地数据发往外部。这是最典型的窃密组合，建议不装。"))
            elif net_lines and cred_lines:
                # 跨窗口共现仍然值得看一眼，但它不是判死项：
                # 大文件里这两件事同时出现是常态，据此否决会冤枉正常工具。
                out.append(_finding("CRED_AND_NET", "risk", "med", 6, False,
                                    e, n, _snip(e.lines[n - 1]),
                                    "同一文件里既有网络请求（第 %d 行）也有凭证读取（第 %d 行），"
                                    "但相距 %d 行，不在同一段流程内" % (n, c, gap),
                                    "核实这两处是否有关联。相距很远通常只是同一个大程序的不同部分。"))
        if re.search(r"b64decode|base64\.b64decode", text) and re.search(r"\b(exec|eval)\s*\(", text):
            for idx, raw in enumerate(e.lines, start=1):
                if re.search(r"\b(exec|eval)\s*\(", raw):
                    out.append(_finding("OBFUSCATED_PAYLOAD", "risk", "high", 26, True,
                                        e, idx, _snip(raw),
                                        "base64 解码后直接执行",
                                        "核实解码内容。混淆执行是刻意隐藏行为，正常 skill 不需要。"))
                    break


def _substantive(lines):
    n = 0
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s.startswith(("#", "//", "--", "/*", "*")):
            continue
        n += 1
    return n


def _check_value(pkg, out, code):
    if not code:
        skill = pkg.find("SKILL.md") or (pkg.entries[0] if pkg.entries else None)
        out.append(_finding("NO_SCRIPTS", "unique", "med", 8, False,
                            skill, 1,
                            "（包内代码文件数 0，共 %d 个条目）" % len(pkg.entries),
                            "包内没有任何脚本，只有文字",
                            "核实它的价值是否只在提示词。纯文字 skill 可与现有 skill 高度重叠，替代成本低。"))
        return
    total = sum(_substantive(e.lines) for e in code)
    if total < 30:
        big = max(code, key=lambda e: (_substantive(e.lines), e.path))
        out.append(_finding("TOO_LITTLE_CODE", "unique", "med", 6, False,
                            big, 1, "（全部脚本有效行合计 %d 行）" % total,
                            "脚本有效行过少，功能可能只是外壳",
                            "核实它是否真在做具体的事。几十行以内通常是别人一段 prompt 就能替代的。"))

    for e in code:
        if e.path.startswith("tests/") or "/tests/" in e.path:
            continue
        sub = _substantive(e.lines)
        if 0 < sub <= 3:
            first = ""
            for raw in e.lines:
                if raw.strip() and not raw.strip().startswith("#"):
                    first = raw
                    break
            out.append(_finding("STUB_CODE", "exec", "med", 5, False,
                                e, 1, _snip(first or "(空)"),
                                "脚本只有 %d 行有效代码，接近空壳" % sub,
                                "核实它是否被真正调用。空壳脚本会让「可执行」这一项虚高。"))

    tests = [e for e in pkg.entries if e.path.startswith("tests/") or "/tests/" in e.path]
    if tests:
        tlines = sum(_substantive(e.lines) for e in tests if e.text)
        if tlines < 15:
            first = tests[0]
            out.append(_finding("TESTS_STUB", "unique", "low", 4, False,
                                first, 1, "（tests 下 %d 个文件，有效行合计 %d）" % (len(tests), tlines),
                                "带 tests 目录但测试内容接近空壳",
                                "核实测试是否真在跑。空壳 tests 会让「有测试」看起来像质量信号，这是可被利用的。"))


def _check_maint(pkg, out):
    # 包内自带的模块名不算外部依赖（本地 import 是正常写法）
    local = set()
    for e in pkg.entries:
        base = e.path.rsplit("/", 1)[-1]
        if base.endswith(".py"):
            local.add(base[:-3])
        elif "/" not in e.path:
            local.add(e.path)
    for e in pkg.select(CODE_EXT):
        mods = set()
        for raw in e.lines:
            m = IMPORT_RE.match(raw)
            if not m:
                continue
            names = m.group(1) or m.group(2) or ""
            for part in names.split(","):
                top = part.strip().split(" ")[0].split(".")[0]
                if top and top.isidentifier():
                    mods.add(top)
        ext = sorted(m for m in mods
                     if m not in STDLIB and m not in ("__future__",) and m not in local)
        for mod in ext:
            out.append(_finding("NONSTDLIB", "maint", "med", 3, False,
                                e, 1, "import " + mod,
                                "依赖非标准库：%s" % mod,
                                "核实是否需要额外安装。要装依赖的 skill 在离线环境里会直接失败。"))
    for e in pkg.entries:
        if not e.binary and e.size > 200 * 1024:
            out.append(_finding("LONG_FILE", "maint", "low", 2, False,
                                e, 1, "（%d 字节）" % e.size,
                                "单文件体积偏大，会占用上下文",
                                "核实是否必须整份读入。大文件可拆成按需读取的片段。"))


def _check_conflict(pkg, out, installed):
    if installed is None:
        return False
    skill = pkg.find("SKILL.md")
    mine = ""
    if skill is not None and skill.text:
        m = re.search(r"description\s*:\s*(.+)", skill.text)
        if m:
            mine = m.group(1).strip().strip('"').strip("'")
    if not mine:
        return True

    def toks(s):
        return set(t for t in re.split(r"[^0-9a-zA-Z\u4e00-\u9fff]+", s.lower()) if len(t) > 1)

    a = toks(mine)
    for item in installed:
        b = toks(item.get("description", ""))
        if not a or not b:
            continue
        inter = len(a & b)
        union = len(a | b)
        ratio = inter / float(union)
        if ratio >= 0.55:
            out.append(_finding("CONFLICT_OVERLAP", "conflict", "high", 4, False,
                                skill, 1, "description: " + mine[:SNIPPET_CAP],
                                "与已装 skill「%s」描述重合度 %.0f%%" % (item.get("name", "?"), ratio * 100),
                                "核实两者职责是否重叠。重叠时上下文会被两份相似说明占掉。"))
        elif ratio >= 0.35:
            out.append(_finding("CONFLICT_OVERLAP", "conflict", "med", 2, False,
                                skill, 1, "description: " + mine[:SNIPPET_CAP],
                                "与已装 skill「%s」描述部分重合（%.0f%%）" % (item.get("name", "?"), ratio * 100),
                                "核实触发词是否互斥。含糊的边界会让两个 skill 抢同一次调用。"))
    return True


DIM_ORDER = {"risk": 0, "exec": 1, "trigger": 2, "unique": 3, "maint": 4, "conflict": 5}
SEV_ORDER = {"high": 0, "med": 1, "low": 2, "info": 3}


def _sort(findings):
    return sorted(findings, key=lambda f: (DIM_ORDER[f["dim"]], SEV_ORDER[f["sev"]],
                                           f["file"], f["line"], f["rule"]))


def _dedupe(findings):
    seen = {}
    for f in findings:
        if f["rule"] in seen:
            seen[f["rule"]]["count"] += 1
            continue
        f["count"] = 1
        seen[f["rule"]] = f
    out = list(seen.values())
    for f in out:
        if f["count"] > 1:
            f["msg"] = "%s（共 %d 处，此处为第一处）" % (f["msg"], f["count"])
    return out


def run(pkg, installed=None):
    out = []
    _check_archive(pkg, out)
    meta, skill, body = _check_structure(pkg, out)
    _check_trigger(pkg, meta, skill, body, out)
    code = _check_code(pkg, out)
    _check_composite(pkg, out)
    _check_value(pkg, out, code)
    _check_maint(pkg, out)
    conflict_evaluated = _check_conflict(pkg, out, installed)
    installable = bool(meta) and bool(meta.get("name")) and bool(meta.get("description"))
    # 没有 SKILL.md 时，触发精度这一维没有任何东西可判。
    # 直接给满分等于「缺席算通过」——空目录因此能拿 74 分，高过真包。
    trigger_evaluable = skill is not None
    return _sort(_dedupe(out)), conflict_evaluated, installable, trigger_evaluable
