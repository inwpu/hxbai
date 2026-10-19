# APK reverse engineering three-step (APK, jadx, Android reverse, NDK, native so, signature certificate, AndroidManifest)

APK 分发题的标准三步逆向法 + 签名证书密钥源模式。

## 第一步：jadx 反编译 + 定位关键逻辑

- `jadx -d out/ app.apk`（超大 APK 用 `--deobf`；卡死就 `jadx-gui` 手选类）
- `AndroidManifest.xml` 先读：exported 组件/deep link/权限
- 搜：`flag`、`Cipher`、`SecretKey`、`native`（native 方法声明 = 进第二步）、`PackageManager`/`GET_SIGNATURES`（签名校验型）

## 签名证书当密钥源（签名校验型的通用 Android 知识）

应用校验自身签名并把它混入密钥派生（flag = XOR/AES(base64 数据, key=证书摘要) 类）——**不破解校验，直接用目标自己的签名证书**：

```bash
unzip -p app.apk 'META-INF/*.RSA' | openssl pkcs7 -inform DER -print_certs \
  | openssl x509 -outform DER | sha256sum     # 证书 DER 摘要 = 密钥材料
```
拿到摘要后喂进 jadx 里定位到的解密函数（python 重实现）。

## 第二步：NDK native so（有 native 方法时）

- `unzip app.apk -d ext/ && ls ext/lib/*/` → `objdump -d`/Ghidra 打开 `.so`
- 识别**协议重实现**线索：导出函数名（`Java_..._encrypt`）、常量（ChaCha20 的 `expand 32-byte k`、AES S-box、自定义魔数）
- Kotlin/Java 层调用参数 = 协议明文结构；so 层 = 加密/打包——两边对齐后**用 python 重实现协议**（`pycryptodome`），不硬啃汇编逐位仿真

## 第三步：一次请求收旗

协议重实现后通常只需构造**一次正确格式的请求**（时间戳+nonce+加密体）发目标端点。curl 恒 403 时按 browser-context-headers 卡处理（变量消去矩阵逐头对照）。

## 工具链

`apktool`（资源/manifest）、`jadx`（dex→java）、`objdump`/`Ghidra`（so）、`apksigner verify --print-certs`（证书提取）、`frida`（动态 hook 兜底）
