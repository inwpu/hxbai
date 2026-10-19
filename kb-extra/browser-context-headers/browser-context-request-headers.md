# Browser context request headers methodology (Sec-Fetch, browser context headers, curl 403, anti-bot, header matrix elimination)

服务端校验「请求是否来自真实浏览器上下文」时的**通用补全方法论**——不是猜哪三个头，是系统化实验。

## 完整浏览器同源 fetch 头集（按层）

### 传输/身份层
```
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Accept-Encoding: gzip, deflate, br
```

### 来源/安全层
```
Referer: https://<host>/<真实入口路径>
Origin: https://<host>            # POST/跨源时
Sec-Fetch-Dest: document          # 三件套——最高频校验对象
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin       # 按实际: none/same-site/cross-site
Sec-Fetch-User: ?1                # 导航触发时
Cookie: <会话>
```

### 客户端提示层（新 Chrome）
```
Sec-CH-UA: "Not_A Brand";v="8", "Chromium";v="120"
Sec-CH-UA-Mobile: ?0
Sec-CH-UA-Platform: "Windows"
```

## 从前端 JS 发现自定义头（应用特有校验）

服务端常校验**自定义头**（`X-App-Resource: page`、`X-Requested-With: XMLHttpRequest` 类）——通用头补全后仍 403 时：
1. 找应用前端 JS（入口 HTML 引用的 bundle）
2. 搜 `headers`/`setRequestHeader`/`fetch(` 的 init 对象——所有自定义头与值都在
3. 把发现的头按同源语境补进请求

## 变量消去矩阵法（定位缺失项——不猜）

1. **基线**：裸请求记录响应
2. **逐头加**：一次加一个头，观察响应差分——记录每个头的边际效应
3. **逐头减**（有完整浏览器请求时）：DevTools 复制完整请求，逐个删头找最小必需集——`-Sec-Fetch-Dest` 突然 403 = 找到了
4. 最小集回放：脚本化重放稳定复现才算成

## 常见坑

- `Sec-Fetch-Site` 的值要与实际来源匹配（same-origin ≠ none ≠ cross-site）——值错同被拒
- 头全带了仍 403 → **TLS 指纹层**（JA3）：curl/python 的 TLS 握手指纹被识别——`curl-impersonate`/真实浏览器代理链
- HSTS/COOP/CORP 是服务端**发**的头，不是你要发的——别搞反
- 值的细节被校验（UA 版本与 Sec-CH-UA 不一致）：全套头要**自洽**（同一浏览器版本族）
