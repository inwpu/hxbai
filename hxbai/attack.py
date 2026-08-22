from __future__ import annotations

import re

TACTICS = [
    ("TA0043", "Reconnaissance"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0010", "Exfiltration"),
]
_TACTIC_ORDER = {t[1]: i for i, t in enumerate(TACTICS)}

TECHNIQUES = {
    "T1595":     ("Active Scanning", "Reconnaissance", {"web", "pentest"}, ["nmap", "port scan", "scan", "ffuf", "gobuster", "dirb"]),
    "T1046":     ("Network Service Discovery", "Discovery", {"pentest", "web"}, ["open port", "service", "/tcp open", "enumerate service"]),
    "T1190":     ("Exploit Public-Facing Application", "Initial Access", {"web", "exploit"}, ["sql injection", "sqli", "ssti", "xxe", "ssrf", "deserialization", "rce", "file upload", "path traversal", "lfi", "prototype pollution", "auth bypass", "cve", "sql注入", "注入", "文件包含", "反序列化", "模板注入", "上传", "路径穿越", "目录遍历", "任意文件", "越权", "远程代码执行", "命令执行", "公网应用"]),
    "T1078":     ("Valid Accounts", "Initial Access", {"web", "cloud", "pentest"}, ["default cred", "admin/", "valid account", "leaked password", "access key", "akia", "login with", "默认口令", "弱口令", "默认密码", "泄露密码", "有效账户", "账号密码"]),
    "T1133":     ("External Remote Services", "Initial Access", {"pentest"}, ["telnet", "ssh", "rdp", "remote login", "vpn", "远程登录", "跳板机"]),
    "T1059":     ("Command and Scripting Interpreter", "Execution", {"web", "exploit"}, ["command injection", "os command", "groovy", "python exec", "bash -c", "code execution", "eval(", "命令注入", "命令执行", "代码执行", "反弹shell", "执行命令"]),
    "T1203":     ("Exploitation for Client Execution", "Execution", {"web"}, ["template injection", "jinja", "render", "模板注入", "渲染"]),
    "T1611":     ("Escape to Host", "Privilege Escalation", {"evasion", "exploit"}, ["sandbox escape", "container escape", "jail escape", "pyjail", "breakout", "沙箱逃逸", "容器逃逸", "逃逸", "越狱", "沙箱"]),
    "T1068":     ("Exploitation for Privilege Escalation", "Privilege Escalation", {"pentest", "exploit"}, ["privesc", "privilege escalation", "suid", "kernel exploit", "sudo", "提权", "权限提升", "本地提权"]),
    "T1548":     ("Abuse Elevation Control Mechanism", "Privilege Escalation", {"cloud", "pentest"}, ["assume role", "assumerole", "sts", "role assumption", "external id"]),
    "T1552":     ("Unsecured Credentials", "Credential Access", {"cloud", "web"}, ["credential in", "hardcoded", "secret", "env var", "config leak", ".env", "password =", "硬编码", "密钥", "配置泄露", "凭据泄露", "源码泄露", "备份泄露", "敏感信息"]),
    "T1552.005": ("Cloud Instance Metadata API", "Credential Access", {"cloud", "web"}, ["169.254.169.254", "imds", "metadata endpoint", "instance metadata", "ssrf metadata", "元数据", "元数据接口"]),
    "T1550":     ("Use Alternate Authentication Material", "Defense Evasion", {"web", "cloud"}, ["jwt", "jwks", "alg none", "token forge", "kid", "session token", "cookie forge", "令牌", "伪造", "签名", "会话", "令牌伪造", "越权认证"]),
    "T1555":     ("Credentials from Password Stores", "Credential Access", {"cloud", "pentest"}, ["secretsmanager", "secret store", "vault", "keychain", "parameter store", "ssm"]),
    "T1212":     ("Exploitation for Credential Access", "Credential Access", {"web"}, ["idor", "bola", "broken access", "leak creds", "越权", "水平越权", "垂直越权", "逻辑漏洞"]),
    "T1580":     ("Cloud Infrastructure Discovery", "Discovery", {"cloud"}, ["list buckets", "describe instances", "list roles", "cloud enum", "get-caller-identity", "cloudfox"]),
    "T1526":     ("Cloud Service Discovery", "Discovery", {"cloud"}, ["list services", "cloud service", "s3 ls", "iam list"]),
    "T1083":     ("File and Directory Discovery", "Discovery", {"web", "pentest"}, ["directory listing", "find /", "ls -la", "enumerate files", "/flag", "目录遍历", "文件枚举", "读目录"]),
    "T1210":     ("Exploitation of Remote Services", "Lateral Movement", {"pentest"}, ["pivot", "internal service", "lateral", "reach internal", "横向", "内网", "跳板", "内网横向", "打内网", "横向移动"]),
    "T1090":     ("Proxy / Tunneling", "Lateral Movement", {"pentest"}, ["chisel", "proxychains", "tunnel", "socks", "port forward", "隧道", "代理", "端口转发", "内网穿透"]),
    "T1530":     ("Data from Cloud Storage", "Collection", {"cloud"}, ["s3 get-object", "download object", "bucket read", "blob", "sas token"]),
    "T1005":     ("Data from Local System", "Collection", {"web", "pentest"}, ["read flag", "cat /flag", "read file", "flag.txt", "读文件", "读取文件", "读flag", "任意文件读取", "文件读取", "凭据"]),
    "T1213":     ("Data from Information Repositories", "Collection", {"web"}, ["database", "db dump", "wiki", "repo secrets"]),
    "T1027":     ("Obfuscated Files or Information", "Defense Evasion", {"evasion"}, ["obfuscate", "encode payload", "base64 wrap", "waf bypass", "filter bypass", "绕过", "混淆", "编码", "免杀", "过滤绕过", "waf绕过"]),
    "T1140":     ("Deobfuscate/Decode", "Defense Evasion", {"evasion", "exploit"}, ["decode", "kms decrypt", "envelope", "decrypt secret", "解码", "解密", "逆向", "反编译", "还原"]),
    "T1567":     ("Exfiltration Over Web Service", "Exfiltration", {"web", "evasion"}, ["oob", "out-of-band", "dns exfil", "callback", "burp collaborator", "exfiltrate", "回连", "外带", "带外", "回调", "数据外带"]),
    "T1211":     ("Exploitation for Defense Evasion", "Defense Evasion", {"evasion"}, ["edr bypass", "av bypass", "detection bypass", "evade detection", "免杀", "检测绕过", "对抗"]),
    "T1087.002": ("Domain Account Discovery", "Discovery", {"pentest"}, ["domain user", "net user /domain", "ldapsearch", "enum4linux", "rid cycl", "get-domainuser", "adidnsdump"]),
    "T1069.002": ("Domain Groups / BloodHound", "Discovery", {"pentest"}, ["bloodhound", "sharphound", "domain admins", "attack path", "acl abuse", "group membership", "azurehound"]),
    "T1482":     ("Domain Trust Discovery", "Discovery", {"pentest"}, ["domain trust", "forest trust", "nltest", "trust relationship", "cross-domain"]),
    "T1558.003": ("Kerberoasting", "Credential Access", {"pentest"}, ["kerberoast", "spn", "getuserspns", "service ticket", "tgs-rep", "rc4 ticket"]),
    "T1558.004": ("AS-REP Roasting", "Credential Access", {"pentest"}, ["as-rep", "asrep", "getnpusers", "no preauth", "dont_req_preauth", "asreproast"]),
    "T1557.001": ("LLMNR/NBT-NS Poison + SMB Relay", "Credential Access", {"pentest"}, ["responder", "llmnr", "nbt-ns", "ntlm relay", "ntlmrelayx", "mitm6", "smb relay", "coerce"]),
    "T1003.006": ("DCSync", "Credential Access", {"pentest"}, ["dcsync", "secretsdump", "drsuapi", "replicate directory", "krbtgt hash", "getchanges"]),
    "T1003":     ("OS Credential Dumping (LSASS/SAM)", "Credential Access", {"pentest"}, ["lsass", "mimikatz", "sekurlsa", "sam dump", "ntds.dit", "hashdump", "procdump lsass"]),
    "T1110.002": ("Password Cracking (hashcat/John)", "Credential Access", {"pentest"}, ["hashcat", "john", "crack hash", "wordlist", "rockyou", "ntlm hash", "mode 13100", "mode 18200"]),
    "T1550.002": ("Pass the Hash", "Lateral Movement", {"pentest"}, ["pass the hash", "pth", "-hashes", "ntlm auth", "wmiexec", "psexec"]),
    "T1550.003": ("Pass the Ticket / Golden", "Lateral Movement", {"pentest"}, ["pass the ticket", "golden ticket", "silver ticket", "ptt", "ticketer", "kirbi", "ccache"]),
    "T1021.002": ("SMB/Windows Admin Shares", "Lateral Movement", {"pentest"}, ["smbexec", "psexec", "admin$", "netexec", "crackmapexec", "impacket"]),
    "T1021.006": ("WinRM", "Lateral Movement", {"pentest"}, ["winrm", "evil-winrm", "5985", "5986", "powershell remoting"]),
}


def match_techniques(text: str, dim: str | None = None, top: int = 4) -> list[str]:
    if not text:
        return []
    low = text.lower()
    scored: list[tuple[int, str]] = []
    for tid, (_name, _tac, dims, kws) in TECHNIQUES.items():
        if dim and dim not in dims:
            continue
        hits = sum(1 for k in kws if k in low)
        if hits:
            scored.append((hits, tid))
    scored.sort(key=lambda x: (-x[0], _TACTIC_ORDER.get(TECHNIQUES[x[1]][1], 99)))
    return [tid for _h, tid in scored[:top]]


def tactic_of(tid: str) -> str:
    t = TECHNIQUES.get(tid)
    return t[1] if t else ""


def technique_name(tid: str) -> str:
    t = TECHNIQUES.get(tid)
    return t[0] if t else tid


GOAL_TACTIC = {
    "recon":  "Reconnaissance",
    "vuln":   "Initial Access",
    "access": "Execution",
    "flag":   "Collection",
    "foothold":  "Initial Access",
    "discovery": "Discovery",
    "privesc":   "Privilege Escalation",
    "lateral":   "Lateral Movement",
    "exfil":     "Exfiltration",
}


def label(tid: str) -> str:
    t = TECHNIQUES.get(tid)
    return f"{tid} ({t[0]} / {t[1]})" if t else tid
