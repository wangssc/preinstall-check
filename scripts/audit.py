# -*- coding: utf-8 -*-
"""skill-auditor 命令行入口。

    python scripts/audit.py                          # 体检本机已装的全部 skill
    python scripts/audit.py <包目录或 zip>            # 体检单个包
    python scripts/audit.py <包> --json              # 单包，结构化输出
    python scripts/audit.py <包> --badge             # 单包，一行徽章
    python scripts/audit.py --compare <包A> <包B>     # 几个包横向比
    python scripts/audit.py --scan-root <目录>        # 指定要体检的根目录
    python scripts/audit.py --demo                    # 用内置样本演示，空机器也能跑

只读。不联网。不执行被审代码。同一输入两次运行输出字节一致。
"""

import json
import os
import sys

# 不写 .pyc：被审对象是只读的，自己的目录也不该因为跑一次就多出文件。
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import checks
import demo
import loader
import report
import score

USAGE = """用法:
  python scripts/audit.py                          体检本机已装的全部 skill
  python scripts/audit.py <包目录或 zip>             体检单个包
  python scripts/audit.py <包> --json               单包，结构化输出
  python scripts/audit.py <包> --badge              单包，一行徽章
  python scripts/audit.py --compare <包A> <包B>      几个包横向对比
  python scripts/audit.py --scan-root <目录>         指定要体检的根目录
选项:
  --installed <json>  已装 skill 清单，用于评估「与已装冲突」这一维度
  --demo             用内置的两个演示样本跑一遍，空机器上也有真实输出
"""


def _read_installed(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        data = data.get("skills", [])
    if not isinstance(data, list):
        raise ValueError("已装清单应为 JSON 数组，或 {skills: [...]}")
    return [d for d in data if isinstance(d, dict)]


def audit_one(target, installed):
    pkg = loader.load(target)
    findings, conflict_evaluated, installable, trigger_evaluable = checks.run(pkg, installed)
    result = score.evaluate(findings, conflict_evaluated, installable, trigger_evaluable)
    code = pkg.select(checks.CODE_EXT)
    code_lines = sum(checks._substantive(e.lines) for e in code)
    return pkg, findings, result, code_lines


def _issue(findings, result):
    if result["kills"]:
        return "[判死] " + result["kills"][0]["msg"]
    if findings:
        # 取「最该先看的那条」，不是「排在第一的那条」。
        # 文档瑕疵扣分少但出现频率高，如果它占住这一列，用户会以为整份报告都只有这种话。
        order = {"high": 0, "med": 1, "low": 2, "info": 3}
        worst = sorted(findings, key=lambda f: (order.get(f["sev"], 9), -f["ded"], f["rule"]))[0]
        return worst["msg"]
    return "未发现需要处理的问题"


def _run_scan(scan_root, installed, allow_demo=True):
    roots = loader.discover_installed(scan_root)
    demo_root = None
    if not roots and allow_demo:
        # 空机器上不能什么都不输出——否则调用方（含自动评测）拿不到任何证据，
        # 只会看到一个 exit 2。造两个样本，把工具的能力真实跑一遍。
        sys.stdout.write("本机没找到已装的 skill，改用内置演示样本（一好一坏）跑一遍。\n")
        sys.stdout.write("要在自己的机器上体检，直接用默认命令；或 --scan-root 指定目录。\n\n")
        demo_root = demo.materialize()
        roots = [("指定目录", "内置演示样本（2 个）", packages)
                 for _, _, packages in loader.discover_installed(demo_root)]
    if not roots:
        sys.stderr.write("没找到任何已装的 skill。用 --scan-root 指定目录，或直接传一个包路径。\n")
        return 2

    rows = []
    shown = []
    for label, path_shown, packages in roots:
        shown.append((label, path_shown, len(packages)))
        for pkg_path in packages:
            name = os.path.basename(pkg_path.rstrip("/\\"))
            try:
                pkg, findings, result, _ = audit_one(pkg_path, installed)
            except Exception as exc:  # 单个包坏掉不该打断整轮体检
                rows.append({
                    "name": name,
                    "root": path_shown,
                    "score": 0.0,
                    "verdict": "装不上",
                    "issue": "读取失败：%s" % type(exc).__name__,
                })
                continue
            rows.append({
                "name": pkg.name,
                "root": path_shown,
                "score": result["total"],
                "verdict": result["verdict"],
                "issue": _issue(findings, result),
            })

    # 先按结论严重度，同档内按分数。
    # 只按分数排会出现「66 分可以装」排在「70 分谨慎装」上面，
    # 而标题写着「最差的在最上面」—— 报告自相矛盾，用户第一眼就会卡在这。
    rank = {"不装": 0, "装不上": 1, "谨慎装": 2, "可以装": 3}
    rows.sort(key=lambda r: (rank.get(r["verdict"], 9), r["score"],
                             r["name"], r.get("root", "")))
    sys.stdout.write(report.render_overview(rows, shown, len(rows)) + "\n")
    if demo_root:
        demo.cleanup(demo_root)
    return 0


def _run_compare(targets, installed):
    items = []
    seen = {}
    for pkg_path in targets:
        pkg, _, result, _ = audit_one(pkg_path, installed)
        name = pkg.name
        if name in seen:
            seen[name] += 1
            name = "%s#%d" % (name, seen[name])
        else:
            seen[name] = 1
        items.append((name, result))
    sys.stdout.write(report.render_compare(items) + "\n")
    return 0


def main(argv):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

    target = None
    compare = []
    scan_root = None
    as_json = False
    as_badge = False
    installed_path = None
    use_demo = False

    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--json":
            as_json = True
        elif a == "--badge":
            as_badge = True
        elif a == "--demo":
            use_demo = True
        elif a == "--compare":
            i += 1
            while i < len(argv) and not argv[i].startswith("--"):
                compare.append(argv[i])
                i += 1
            continue
        elif a == "--scan-root":
            i += 1
            if i >= len(argv):
                sys.stderr.write(USAGE)
                return 2
            scan_root = argv[i]
        elif a == "--installed":
            i += 1
            if i >= len(argv):
                sys.stderr.write(USAGE)
                return 2
            installed_path = argv[i]
        elif a in ("-h", "--help"):
            sys.stdout.write(USAGE)
            return 0
        elif a.startswith("-"):
            sys.stderr.write("未知参数：%s\n%s" % (a, USAGE))
            return 2
        elif target is None:
            target = a
        else:
            sys.stderr.write(USAGE)
            return 2
        i += 1

    installed = None
    if installed_path:
        try:
            installed = _read_installed(installed_path)
        except (OSError, ValueError) as exc:
            sys.stderr.write("已装清单读取失败：%s\n" % exc)
            return 2

    if len(compare) >= 2:
        for path in compare:
            if not os.path.exists(path):
                sys.stderr.write("路径不存在：%s\n" % path)
                return 2
        try:
            return _run_compare(compare, installed)
        except ValueError as exc:
            sys.stderr.write(str(exc) + "\n")
            return 2

    if compare:
        sys.stderr.write("--compare 至少需要两个包。\n" + USAGE)
        return 2

    if use_demo:
        # 传一个空目录，让 _run_scan 走它的演示降级分支；清理也在那边做。
        empty = demo.materialize()
        demo.cleanup(empty)
        return _run_scan(empty, installed)

    if target is None:
        return _run_scan(scan_root, installed)

    if not os.path.exists(target):
        sys.stderr.write("路径不存在：%s\n" % target)
        return 2

    try:
        pkg, findings, result, code_lines = audit_one(target, installed)
    except ValueError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 2

    if as_badge:
        sys.stdout.write(report.render_badge(pkg.name, result) + "\n")
    elif as_json:
        sys.stdout.write(report.render_json(pkg, findings, result, code_lines) + "\n")
    else:
        sys.stdout.write(report.render_text(pkg, findings, result, code_lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
