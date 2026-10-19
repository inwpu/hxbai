# SSO / auth portal information gathering & JWT/SSO quick checks (SSO, unified authentication, onboarding, directory, PoW login, JWT, OAuth, SAML)

统一认证门户（SSO/登录聚合型）的**信息收集 checklist + 令牌速查**。

## 信息收集面（按序打勾）

1. **onboarding/帮助/示例端点**：`/onboarding`、`/onboarding/sample`、`/help`、`/demo`、`/docs`——常泄**真实样本凭据的形态**（3 个样本 → 逆向口令生成规则）
2. **directory/通讯录端点**：`/directory`、`/api/users`、`/api/contacts`——拿全量用户名 + **账号元数据**（创建时间/最后登录/最后改密）——**用账号元数据找陈旧凭据**（从未登录/长期未改密的账号群 = 默认口令未改的高危面）
3. **公开注册/找回流程**：找回流程泄露口令规则（错误信息回显"口令须含…"）；注册流程的默认口令策略
4. **PoW（proof-of-work）登录**：响应头/登录页 JS 里的 PoW 挑战——按 JS 算法（多为 sha256 前导零/Nonce 枚举）脚本化求解，**不要手算**

## 打法顺序

样本凭据形态 → 口令规则 → directory 元数据筛陈旧账号 → 规则生成候选口令表 →（PoW 求解器）→ 批量登录。**改过密的活跃账号不碰**——从陈旧群找一个能登的即入。

## JWT 速查（发到 eyJ 开头令牌时）

| 攻击 | 操作 |
|---|---|
| 算法混淆 | `alg: none` / HS256↔RS256 混淆（公钥当 HMAC 密钥） |
| kid 注入 | `kid` 路径穿越读任意文件/SQLi/命令注入 |
| 弱 HMAC 密钥 | jwt2john + 字典爆破（`rockyou`） |
| exp/aud 缺失 | 漏验字段直接伪造（`aud` 换 user_id 提权） |
| JWK/x5u 注入 | header 内嵌自签公钥/远程拉取 x5u |

## OAuth/OIDC/SAML 速查

- `state`/`nonce` 缺失 → CSRF 绑定攻击
- 回调 redirect_uri 校验缺失/过宽（子串匹配）→ 开放重定向盗 code
- `/.well-known/openid-configuration`、`/saml/metadata`——配置端点先读（issuer/支持的 scope/回调白名单全在那）
- SAML：`XMLSignature` 包装（WXX1/WXX3）、`AudienceRestriction` 删除重签

## 企业 LDAP 型

匿名 bind → `namingContexts` → 全树 dump → 密码策略属性（`pwdLastSet` 类）找陈旧凭据。
