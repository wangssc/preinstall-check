# -*- coding: utf-8 -*-
"""打分：扣分制，默认信任，发现风险才扣。

权重按「装错的代价」分配，不按「功能多少」分配：
  权限风险 35  装错一次的代价不可撤销（数据被删、凭证被读走）
  可执行性 20  跑不起来是常见的白装，代价中等但概率最高
  触发精度 20  乱触发会污染上下文、抢掉别的 skill 的活，代价中等
  不可替代性 15  只是白装，代价最低但发生频率高
  维护成本 6   换机器/换版本跑不动，代价低
  冲突 4       与已装 skill 重叠，代价最低（最多是上下文浪费）

判死项独立于总分：命中任一 kill 规则直接给「不装」，不参与加权。
"""

from __future__ import annotations

WEIGHTS = [
    ("risk", 35, "权限风险"),
    ("exec", 20, "可执行性"),
    ("trigger", 20, "触发精度"),
    ("unique", 15, "不可替代性"),
    ("maint", 6, "维护成本"),
    ("conflict", 4, "与已装冲突"),
]

MAX_TOTAL = sum(w for _, w, _ in WEIGHTS)


def evaluate(findings, conflict_evaluated, installable=True, trigger_evaluable=True):
    dims = []
    for key, weight, label in WEIGHTS:
        if key == "conflict":
            evaluated = conflict_evaluated
        elif key == "trigger":
            evaluated = trigger_evaluable
        else:
            evaluated = True
        lost = sum(f["ded"] for f in findings if f["dim"] == key)
        got = max(0, weight - lost) if evaluated else 0
        # 扣分可以超过本维度上限（多条规则叠加），但报告里不能写「扣 22 / 20」：
        # 那会让用户怀疑整套算术，而且溢出的分没有落到任何维度。
        overflow = max(0, lost - weight)
        dims.append({
            "key": key,
            "label": label,
            "weight": weight,
            "score": got,
            "evaluated": evaluated,
            "lost": lost if evaluated else 0,
            "lost_shown": min(lost, weight) if evaluated else 0,
            "overflow": overflow if evaluated else 0,
            "note": ("需 --installed 提供已装清单" if key == "conflict"
                     else "包内没有 SKILL.md，无可判内容" if key == "trigger"
                     else ""),
            "hits": len([f for f in findings if f["dim"] == key]),
        })

    total = sum(d["score"] for d in dims)
    covered = sum(d["weight"] for d in dims if d["evaluated"])
    coverage = covered / float(MAX_TOTAL)

    kills = [f for f in findings if f["kill"]]
    empty = [f for f in findings if f["rule"] == "EMPTY_BODY"]
    risk_dim = [d for d in dims if d["key"] == "risk"][0]
    if kills:
        verdict = "不装"
        reason = "命中 %d 条判死项，与总分无关" % len(kills)
    elif not installable:
        verdict = "装不上"
        # 结构不成立时总分不可用：空目录能拿 74 分（没有代码可扫就没得扣），
        # 反而高过有脚本有测试的真包。分数在这里只说明「其余维度没发现问题」。
        reason = ("入口缺失或 frontmatter 不完整，按现状无法注册为 skill。"
                  "总分仅供参考：结构不成立时它不代表可用性")
    elif empty:
        # 独立的门，不是判死项：它不会造成不可逆损害，所以不混进判死清单；
        # 但它也不能靠总分放行——空壳包和真包会挤进同一档。
        verdict = "不装"
        reason = "正文不足 80 字，没有可执行内容；下面的分数只说明它差在哪，不构成可装理由"
    elif total < 40:
        # 只兜「整体不可用」，不兜「风险项多」。原来的门槛是 60，结果是 59 分报「不装」、
        # 60 分报「谨慎装」—— 1 分之差决定装不装，这种结论没法向用户解释，也没法复核。
        # 40 的意思是：风险维度已经塌到零，同时至少还有一个 20 分的维度掉了六成以上。
        verdict = "不装"
        reason = "风险与可用性同时崩塌，不是靠核实某一条就能救回来的包"
    elif [f for f in findings if f["sev"] == "high"]:
        # 结论按严重度分档，不按总分分档。
        # 原因：总分把「文档没写何时用」和「脚本读 SSH 私钥」压成同一个数字，
        # 结果就是好包和坏包一起被推上「谨慎装」——真实数据里 32 个包有 24 个落进这一档，
        # 用户第一眼看到自己天天在用的 pdf、docx 被判「需核实」，就再也不信这个工具了。
        verdict = "谨慎装"
        reason = "命中高危项，逐条核实证据后再决定"
    elif risk_dim["score"] < risk_dim["weight"] * 0.5:
        # 风险项扎堆，但每一条单独都不够 high（典型是本地服务类工具：开端口、调子进程、
        # 清理临时目录，单看全是本职行为）。这时候不能靠总分否决——3000 行的包必然
        # 命中更多规则，按总分算等于系统性歧视大包。所以只降结论档位，不下「不装」。
        verdict = "谨慎装"
        reason = "没有单条高危项，但风险面扣掉了 %d/%d，值得先看一眼证据" % (
            risk_dim["lost_shown"], risk_dim["weight"])
    else:
        verdict = "可以装"
        reason = "无高危项；扣分都在文档瑕疵类，不影响能不能用"
    if coverage < 0.85 and verdict == "可以装":
        verdict = "谨慎装"
        reason = "覆盖不足（%.0f%%），结论基于不完整信息" % (coverage * 100)

    return {
        "total": round(total, 1),
        "max_total": MAX_TOTAL,
        "coverage": round(coverage * 100, 1),
        "verdict": verdict,
        "reason": reason,
        "dims": dims,
        "kills": kills,
    }
