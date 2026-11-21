# -*- coding: utf-8 -*-
"""渲染：人话版 + JSON。不含时间戳、不含绝对路径、不含随机量。"""

from __future__ import annotations

import json
import unicodedata

SEV_LABEL = {"high": "高", "med": "中", "low": "低", "info": "提示"}
BAR = "=" * 62
ORDER = ["不装", "装不上", "谨慎装", "可以装"]


def _dw(text):
    """显示宽度：CJK 记 2 列。用于让终端表格真正对齐。"""
    width = 0
    for ch in text:
        width += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return width


def _pad(text, width):
    return text + " " * max(0, width - _dw(text))


def _root_tag(root):
    """把 ~/.workbuddy/skills 压成 workbuddy，用于区分同名包。"""
    parts = [p for p in root.replace("\\", "/").split("/") if p]
    if len(parts) >= 2:
        return parts[-2].lstrip(".")[:8]
    return (root or "")[:8]


def _cut(text, width):
    if _dw(text) <= width:
        return text
    out = ""
    for ch in text:
        if _dw(out + ch) > width - 1:
            break
        out += ch
    return out + "…"


def _num(v, width):
    return str(v).rjust(width)


def render_text(pkg, findings, result, code_lines):
    out = []
    out.append(BAR)
    out.append("装前安检报告   启发式评分，有误差，不是安全审计")
    out.append(BAR)
    out.append("包名：%s    形态：%s    文件数：%d    脚本有效行：%d"
               % (pkg.name, "目录" if pkg.form == "dir" else "zip",
                  len(pkg.entries), code_lines))
    out.append("")

    out.append("结论：%s" % result["verdict"])
    out.append("总分：%.1f / %d    覆盖：%.0f%%"
               % (result["total"], result["max_total"], result["coverage"]))
    out.append("依据：%s" % result["reason"])
    out.append("")

    if result["kills"]:
        out.append("判死项（与总分无关，命中即否决）")
        for f in result["kills"]:
            out.append("  [判死] %s  %s:%d" % (f["rule"], f["file"], f["line"]))
            out.append("    证据：%s" % f["snippet"])
            out.append("    判断：%s" % f["msg"])
            out.append("    建议：%s" % f["adv"])
        out.append("")
    else:
        out.append("判死项：无")
        out.append("")

    out.append("分维度")
    for d in result["dims"]:
        if not d["evaluated"]:
            out.append("  %s  %s / %d   未评估（%s）"
                       % (d["label"].ljust(5, "　"), "—", d["weight"],
                          d.get("note") or "信息不足"))
        else:
            line = ("  %s  %s / %d   命中 %d 项，扣 %.0f"
                    % (d["label"].ljust(5, "　"), _num("%.1f" % d["score"], 5),
                       d["weight"], d["hits"], d["lost_shown"]))
            if d.get("overflow"):
                line += ("（另有 %d 分超出该维度上限，已归零未计入）"
                         % d["overflow"])
            out.append(line)
    out.append("")

    out.append("发现明细（%d 条，每条都指到原文）" % len(findings))
    for i, f in enumerate(findings, start=1):
        out.append("  %d. [%s] %s  ← %s:%d"
                   % (i, SEV_LABEL[f["sev"]], f["rule"], f["file"], f["line"]))
        out.append("     证据：%s" % f["snippet"])
        out.append("     判断：%s" % f["msg"])
        out.append("     建议：%s" % f["adv"])
    if not findings:
        out.append("  （无）")
    out.append("")

    out.append("文件树（./ 相对包根，共 %d 项）" % len(pkg.entries))
    for e in pkg.entries:
        mark = ""
        if e.binary:
            mark = "  [二进制]"
        elif e.truncated:
            mark = "  [已截断]"
        if e.symlink_target is not None:
            mark = "  -> " + e.symlink_target
        out.append("  ./%s%s" % (e.path, mark))
    out.append("")
    out.append("说明：本报告为启发式判断，基于结构与文本模式，不执行被审代码。")
    out.append("      高分不等于安全，低分不等于有害；每条结论都可按上面的行号复核。")
    return "\n".join(out)


def render_json(pkg, findings, result, code_lines):
    payload = {
        "package": {
            "name": pkg.name,
            "form": pkg.form,
            "files": len(pkg.entries),
            "code_lines": code_lines,
        },
        "verdict": result["verdict"],
        "reason": result["reason"],
        "score": result["total"],
        "max_score": result["max_total"],
        "coverage_pct": result["coverage"],
        "dimensions": [
            {
                "key": d["key"],
                "label": d["label"],
                "weight": d["weight"],
                "score": d["score"],
                "evaluated": d["evaluated"],
                "deducted": d["lost_shown"],
                "deducted_raw": d["lost"],
                "overflow": d["overflow"],
                "findings": d["hits"],
            }
            for d in result["dims"]
        ],
        "kill_hits": [f["rule"] for f in result["kills"]],
        "findings": [
            {
                "rule": f["rule"],
                "dimension": f["dim"],
                "severity": f["sev"],
                "deduction": f["ded"],
                "kill": f["kill"],
                "occurrences": f["count"],
                "evidence": {
                    "file": f["file"],
                    "line": f["line"],
                    "snippet": f["snippet"],
                },
                "message": f["msg"],
                "advice": f["adv"],
            }
            for f in findings
        ],
        "tree": ["./" + e.path for e in pkg.entries],
        "disclaimer": "启发式评分，有误差；不执行被审代码，不构成安全审计结论。",
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)


# ---------------------------------------------------------------- 批量与对比

def render_overview(rows, roots, total):
    """本机体检总览。rows 已按「结论严重度 → 分数」排序。"""
    out = []
    out.append(BAR)
    out.append("装前安检报告   启发式评分，有误差，不是安全审计")
    out.append(BAR)
    out.append("")
    specified = any(label == "指定目录" for label, _, _ in roots)
    out.append("范围：%s（只看文本，未执行任何被审代码，未修改文件）"
               % ("指定目录" if specified else "本机已装 skill"))
    for label, shown, count in roots:
        out.append("  %s  %s 个" % (_pad(shown, 30), count))
    out.append("合计：%d 个包" % total)
    out.append("")

    counts = {}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1

    parts = []
    for key in ORDER:
        if counts.get(key):
            label = {"不装": "建议卸掉", "装不上": "装不上",
                     "谨慎装": "需核实", "可以装": "可以留"}[key]
            parts.append("%d 个%s" % (counts[key], label))
    if not parts:
        out.append("结论：一个包都没扫到")
        return "\n".join(out)
    out.append("结论：共 %d 个包 — %s" % (total, "，".join(parts)))
    worst = rows[0] if rows else None
    if worst is not None and worst["verdict"] in ("不装", "装不上"):
        out.append("最该先看：%s %.1f（%s）" % (worst["name"], worst["score"],
                                            _cut(worst["issue"], 40)))
    out.append("")

    out.append("明细（按严重度排，最差的在最上面）")
    # 同名包要能区分：本机三个 ego-browser 分别装在 workbuddy / claude / codebuddy 下，
    # 只写包名的话用户不知道「哪个该卸」，那一行结论就没有执行价值。
    dup = {}
    for row in rows:
        dup[row["name"]] = dup.get(row["name"], 0) + 1
    out.append("  分数  结论    %s主要问题" % _pad("名称", 22))
    for row in rows:
        label = row["name"]
        if dup.get(label, 0) > 1:
            label = "%s@%s" % (label, _root_tag(row.get("root", "")))
        out.append("  %5s  %s%s%s" % (
            "%.1f" % row["score"],
            _pad(row["verdict"], 8),
            _pad(_cut(label, 22), 22),
            _cut(row["issue"], 26)))
    out.append("")

    top = max(counts.values()) if counts else 0
    out.append("分档")
    for key in ORDER:
        n = counts.get(key, 0)
        if not n:
            continue
        width = max(1, int(round(n * 20.0 / top))) if top else 0
        out.append("  %s%4d  %s" % (_pad(key, 8), n, "█" * width))
    out.append("")

    out.append("下一步")
    out.append("  看某一个的完整证据：python scripts/audit.py <包路径>")
    out.append("  挑两个比一比：      python scripts/audit.py --compare <包A> <包B>")
    out.append("")
    out.append("说明：分数低只代表「按结构、权限、可读性判断有可疑处」，不是定罪。")
    out.append("      每一条都可以按行号回到原文复核。")
    return "\n".join(out)


def render_compare(items):
    """items: [(名称, 结果 dict)]，顺序为传入顺序。"""
    names = [name for name, _ in items]
    width = max(14, max(_dw(n) for n in names) + 2)

    out = []
    out.append(BAR)
    out.append("skill-auditor 对比   启发式评分，有误差，不是安全审计")
    out.append(BAR)
    out.append("")
    out.append("对比 %d 个包" % len(items))
    out.append("")
    out.append("  " + _pad("维度", 14) + "".join(_pad(n, width) for n in names))

    base = items[0][1]
    for i, dim in enumerate(base["dims"]):
        if not dim["evaluated"]:
            continue
        cells = []
        for _, res in items:
            d = res["dims"][i]
            cells.append(_pad("%.1f/%d" % (d["score"], d["weight"]), width))
        out.append("  " + _pad(dim["label"], 14) + "".join(cells))

    out.append("")
    out.append("  " + _pad("总分", 14) + "".join(_pad("%.1f" % r["total"], width) for _, r in items))
    out.append("  " + _pad("结论", 14) + "".join(_pad(r["verdict"], width) for _, r in items))
    out.append("")

    clean = [(n, r) for n, r in items if not r["kills"]]
    if clean:
        best = max(clean, key=lambda item: item[1]["total"])
        out.append("建议：优先 %s（%.1f 分，未命中判死项）" % (best[0], best[1]["total"]))
    else:
        out.append("建议：%d 个包全部命中判死项，都不建议装" % len(items))
    out.append("")
    out.append("说明：分维度看比看总分可靠。总分接近时，看「权限风险」那一行谁更高。")
    return "\n".join(out)


def render_badge(name, result):
    """一行纯文本徽章，可贴 README。不依赖任何外部服务。"""
    return "%s · %.0f/100 · %s · skill-auditor" % (
        name, result["total"], result["verdict"])
