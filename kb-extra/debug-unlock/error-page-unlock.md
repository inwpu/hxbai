# Error page unlock & root-cause visibility (error page unlock, showReport, stack trace, debug switch, blank 500, ErrorReportValve, Whitelabel)

错误回显被吞（空白 500、通用错误页、静默失败）时的**先解锁再继续**方法论——纯纪律卡，适用面最宽。

## 跨栈解锁面 checklist（按栈逐行打勾）

### Java / Spring / Tomcat
- `ErrorReportValve.showReport=true` + `showServerInfo=true`（Jolokia/MBean 可写时直接 set）——真实异常文本浮出
- Spring Boot：`server.error.include-message=always`、`server.error.include-stacktrace=always`（运行时 env/properties 可改）；**Whitelabel Error Page** 出现 = 默认吞栈——就是本卡的形态
- Actuator 在场：`/actuator/trace`、`/actuator/heapdump`（异常与会话常驻内存，dump 里捞）

### Python / Node / PHP
- Flask：`app.debug=True`（pin 绕过链）/`PROPAGATE_EXCEPTIONS`
- Django：`DEBUG=True`（settings 可写时）
- PHP：`display_errors=On`（.htaccess/.user.ini/env 注入点）
- Node：`NODE_ENV=development`

### 通用
- 包装端点：找**回显包装**的 API（`?debug=1`、`X-Debug: true`、`/api/error` 转发真实栈）
- 日志侧读：应用错误日志路径（`/var/log/app/*.log`——配合文件读原语）
- **二次触发**：解锁后必须**重新触发同一个错误**才看到新回显（旧响应不变）

## 报错被吞时的差分调试 + 单变量对照

- 每次只改**一个**变量（头/参数/编码/分支），A/B 对照记录边际效应——与引擎 DECIDE 的 ROOT-CAUSE VISIBILITY 纪律互为表里
- 二分定位：输入空间二分（前半/后半）找触发子串——被吞的错误也能二分出「哪段输入触发」

## 纪律

错误被吞 → 解锁优先于重试。盲试不带新信息的重试 = 纯烧预算。解锁全失败才降级（日志读/盲注 oracle/时延信道）。
