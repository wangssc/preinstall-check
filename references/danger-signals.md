# 危险信号库

规则 id 与代码里 `scripts/checks.py` 的 `rule` 字段一一对应。扣分值为单条规则的上限，
同一规则命中多处只扣一次（报告里写「共 N 处」）。

## 判死类（命中即「不装」，与总分无关）

| 规则 | 扣分 | 看什么 | 怎么核实 |
|---|---|---|---|
| `UNSAFE_ZIP_ENTRY` | 35 | zip 条目名含 `..`、以 `/` 开头、或带盘符 | 不用核实。这种包不打开，直接弃用 |
| `CRED_ACCESS` | 30 | `.ssh/`、`id_rsa`、`id_ed25519`、`.aws/credentials`、`.netrc`、`.kube/config`、`Library/Keychains` | 搜这段路径出现在哪个函数里，看它读完之后做了什么 |
| `DESTRUCTIVE_HARD` | 30 | `rm -rf /`、`shutil.rmtree("/")`、`mkfs`、`dd if=`、`format C:` | 看清理逻辑是否由用户显式指定路径 |
| `NET_EXFIL` | 28 | 同一文件里既有凭证路径又有网络请求，**且两处相距 ≤ 40 行** | 看发送的 body 是不是从凭证文件读出来的。只同文件不判死：3000 行的服务脚本里两件事必然都出现 |
| `OBFUSCATED_PAYLOAD` | 26 | `b64decode` 与 `exec` / `eval` 同文件 | 解开 base64 看是什么。正常 skill 不需要藏 |

## 高风险（扣分但不判死）

| 规则 | 扣分 | 说明 | 怎么核实 |
|---|---|---|---|
| `HARDCODED_TOKEN` | 14 | `sk-…`、`ghp_…`、`AKIA…`、`xox?-…`、PEM 私钥头、长 Bearer 串 | 区分示例串与真凭证。真凭证视为已泄露 |
| `WRITE_OUTSIDE` | 12 | `open("/etc/…")`、`Path("/usr/…")` | 看写入内容与回滚方式 |
| `CRED_MENTION` | 6 | `.env`、`API_KEY`、`SECRET_KEY`、`os.environ[...]` | 看读的是哪几个键、有没有外传 |
| `SYMLINK_ESCAPE` | 10 | 包内软链接指向包外 | 看目标路径是否在工作目录内 |
| `PICKLE` | 14 | `pickle.load(s)`、`marshal.loads`、`yaml.load()` | 反序列化的数据来自哪里。来自外部等同执行外部代码，所以是 high 不是提示 |

## 中风险

| 规则 | 扣分 | 说明 | 怎么核实 |
|---|---|---|---|
| `SUBPROC` | 10 | `subprocess.*`、`os.system`、`os.popen` | 命令是写死的还是拼出来的。拼的就危险 |
| `SHELL_TRUE` | 8 | `shell=True` | 看有没有用户输入拼进命令串 |
| `EVAL_EXEC` | 8 | `eval(`、`exec(` | 被执行的内容来自网络或文件时等同后门 |
| `NET_CALL` | 8 | `urlopen`、`requests.get/post`、`socket.socket` | 看目标域名与发送内容 |
| `DESTRUCTIVE_SOFT` | 6 | `os.remove`、`unlink`、`rmtree` | 看删除路径是否用户显式给出、有无二次确认 |
| `CRED_AND_NET` | 6 | 同文件里既有凭证读取又有网络请求，但相距 > 40 行 | 隔着几百行的两件事通常只是同一程序的不同部分，核实是否有关联即可 |

## 低风险

| 规则 | 扣分 | 说明 |
|---|---|---|
| `NET_IMPORT` | 4 | 引入了网络库（可能未使用） |
| `TODO_MARK` | 2 | 残留 `TODO` / `FIXME`，常集中在没做完的主路径 |
| `ABS_PATH` | 2 | 写死 `/Users/…`、`/home/…`、`C:\Users\…`。先分辨是文档示例还是真实默认值 |
| `LONG_FILE` | 2 | 单文件 > 200 KB，会吃上下文 |
| `TREE_TRUNCATED` | 2 | 文件数超过 20000，扫描被截断 |

## 结构与可执行

| 规则 | 维度 | 扣分 | 说明 |
|---|---|---|---|
| `MISSING_SKILL_MD` | 可执行性 | 14 | 包根没有 SKILL.md，装不上 |
| `NO_FRONTMATTER` | 可执行性 | 12 | SKILL.md 开头不是 `---` 或没有闭合 |
| `FRONTMATTER_FIELD` | 可执行性 | 7 | 缺 `name` 或缺 `description`（两者各记一次） |
| `SYNTAX_ERROR` | 可执行性 | 10 | Python 文件过不了 `ast.parse` |
| `STUB_CODE` | 可执行性 | 5 | 单个脚本有效代码 ≤ 3 行（tests 目录除外） |
| `BROKEN_REF` | 可执行性 | 3 | 正文写了某个脚本路径，包里没有这个文件 |

## 触发精度

| 规则 | 扣分 | 判定 |
|---|---|---|
| `VAGUE_DESC` | 8 | description 去空格后不足 40 字 |
| `EMPTY_BODY` | 20 | 正文不足 80 字。**独立门：命中即「不装」**，理由不是扣分多，是「包里没有内容」这件事不能靠扣分表达——它会让空包和真包挤进同一档 |
| `THIN_BODY` | 12 | 正文 80–300 字，有内容但不足以构成流程 |
| `BROAD_TRIGGER` | 5 | 出现「任何任务 / 任何需求 / 所有需求 / 万能 / 什么都能 / anything you」 |
| `NO_WHEN_TO_USE` | 5 | 正文没有「何时用 / 适用场景」 |
| `NO_WHEN_NOT` | 3 | 正文没有「何时不用 / 不适用」 |
| `NO_OUTPUT_SPEC` | 3 | 正文没有「输出格式 / 产物」 |
| `NAME_MISMATCH` | 2 | frontmatter 的 name 与目录名不一致（zip 形态不判，因为下载文件名不可控） |

## 不可替代性

| 规则 | 扣分 | 判定 |
|---|---|---|
| `NO_SCRIPTS` | 8 | 包里没有任何脚本，只有文字 |
| `TOO_LITTLE_CODE` | 6 | 全部脚本有效行合计 < 30 |
| `TESTS_STUB` | 4 | 有 tests 目录，但有效行合计 < 15 |

`TESTS_STUB` 存在的原因：空壳 tests 是这条链上最容易被利用的一处——
加一个 3 行的空壳测试文件就能拿到「有测试」的印象分。这条规则专门拆掉它。

## 冲突

| 规则 | 扣分 | 判定 |
|---|---|---|
| `CONFLICT_OVERLAP` | 4 / 2 | 与已装 skill 的 description 词集 Jaccard ≥ 0.55 / ≥ 0.35 |

需要 `--installed` 提供清单才评估。不提供则该维度整段标「未评估」，4 分不计入总分。
