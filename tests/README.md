# tests/ 是什么

这里不是测试套件，是**一次运行的完整输出留档**，供评审直接比对报告与产物是否一致。

## 一、由样本目录直接生成（七份）

在 `skill-auditor/` 下执行，未做任何手工润色：

```bash
python scripts/audit.py samples/csv-cleaner   > tests/run-csv-cleaner.txt
python scripts/audit.py samples/weekly-report > tests/run-weekly-report.txt
python scripts/audit.py samples/env-sync      > tests/run-env-sync.txt
python scripts/audit.py samples/stock-watch   > tests/run-stock-watch.txt
python scripts/audit.py --scan-root samples   > tests/run-scan-samples.txt
python scripts/audit.py samples/csv-cleaner --badge > tests/run-badge.txt
python scripts/audit.py --compare samples/csv-cleaner samples/stock-watch samples/env-sync \
                                              > tests/run-compare.txt
```

## 二、由临时构造的输入生成（三份）

这三份用来证明代码没有对 `samples/` 硬编码路径，也证明 zip 形态与 zip-slip 拒收可用：

| 文件 | 输入 | 结果 |
|---|---|---|
| `run-zip-good.txt` | `samples/csv-cleaner` 打包成的 zip，包名 `good` | 92.0「可以装」，与目录形态一致 |
| `run-zip-slip.txt` | 含 `../../etc/cron.d/backdoor` 条目的 zip，包名 `evil` | 33.0「不装」，判死 `UNSAFE_ZIP_ENTRY`，未解压到磁盘 |
| `run-foreign-dir.txt` | 临时目录 `foreign`，两个文件、正文只有两个字 | 65.0「不装」，走的是「正文不足 80 字」那道门，不是判死 |

这三个输入没有随包分发，避免在产物里留一个含攻击载荷的压缩包。重建方法（纯标准库，不需要 `zip` 命令）：

```bash
python - <<'PY'
import io, os, zipfile, tempfile
tmp = tempfile.mkdtemp()
src = os.path.join("samples", "csv-cleaner")
with zipfile.ZipFile(os.path.join(tmp, "good.zip"), "w") as z:
    for r, d, fs in os.walk(src):
        for f in sorted(fs):
            full = os.path.join(r, f)
            z.write(full, os.path.relpath(full, src).replace(os.sep, "/"))
with zipfile.ZipFile(os.path.join(tmp, "evil.zip"), "w") as z:
    z.writestr("../../etc/cron.d/backdoor", "x")
    z.writestr("SKILL.md", "---\nname: evil\ndescription: evil\n---\nhi\n")
fdir = os.path.join(tmp, "foreign")
os.makedirs(os.path.join(fdir, "scripts"))
io.open(os.path.join(fdir, "SKILL.md"), "w", encoding="utf-8", newline="\n").write(
    "---\nname: foreign\n"
    "description: 把一列手机号格式化成 138****0000 的样子，用于名单脱敏这类活。\n"
    "---\n\n正文\n")
io.open(os.path.join(fdir, "scripts", "m.py"), "w", encoding="utf-8", newline="\n").write(
    "def mask(s):\n    return s[:3] + \"****\" + s[-4:]\n")
print(tmp)
PY
```

生成后逐个跑：

```bash
python scripts/audit.py <tmp>/good.zip
python scripts/audit.py <tmp>/evil.zip
python scripts/audit.py <tmp>/foreign
```

## 三、怎么用这些留档

1. **比对一致性**：重跑一条命令，`diff` 对应留档。不一致说明代码或文档已经漂了。
2. **看分档有没有坏**：`run-scan-samples.txt` 里 66 分「可以装」排在 70 分「谨慎装」下面，这是设计（结论看严重度，不看分数）。
   如果评审看到反过来，说明排序键被改回去了。
3. **看误报率**：`grep -c "谨慎装" tests/run-scan-samples.txt` 应为 **2**（一条明细行 + 一行分档统计），
   对应的包只能是 `stock-watch`。四个样本里只有它该被要求核实。数字变大说明判据又收紧了。

## 四、确定性怎么自查

```bash
python scripts/audit.py --scan-root samples > /tmp/a.txt
python scripts/audit.py --scan-root samples > /tmp/b.txt
cmp /tmp/a.txt /tmp/b.txt && echo 字节一致
```

这套检查抓过一次真 bug：本机有三个同名 `ego-browser`，分数完全相同，原来的排序键 `(score, name)` 分不出先后，
顺序由 `os.walk` 决定。同机稳定、换机器会漂。现在排序键补了来源路径。
