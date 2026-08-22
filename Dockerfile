FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    NODE_VERSION=20.18.1 LANG=C.UTF-8

RUN rm -f /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null; \
    printf 'deb http://mirrors.tuna.tsinghua.edu.cn/kali kali-rolling main non-free non-free-firmware contrib\ndeb http://mirrors.ustc.edu.cn/kali kali-rolling main non-free non-free-firmware contrib\n' \
        > /etc/apt/sources.list && \
    printf '[global]\nindex-url = https://mirrors.bfsu.edu.cn/pypi/web/simple\ntimeout = 120\n[install]\ntrusted-host = mirrors.bfsu.edu.cn\n' \
        > /etc/pip.conf && \
    printf 'Acquire::Retries "10";\nAcquire::http::Timeout "40";\nAcquire::https::Timeout "40";\n' \
        > /etc/apt/apt.conf.d/80-retries

RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections; \
    set -eux; for i in 1 2 3 4 5; do \
        apt-get update && apt-get install -y --no-install-recommends --fix-missing \
            python3 python3-pip python3-venv \
            curl wget git ca-certificates gnupg xz-utils unzip zip xxd file jq ripgrep \
            nmap masscan ffuf gobuster dirb nikto whatweb \
            dnsutils iputils-ping net-tools netcat-traditional ncat socat proxychains4 tmux rlwrap sshpass openssh-client \
            gdb gdb-multiarch radare2 binutils patchelf cpio qemu-user-static ruby ruby-dev build-essential \
            strace ltrace upx-ucl tcpdump \
            hydra john hashcat \
            tshark binwalk foremost exiftool steghide sleuthkit poppler-utils mono-mcs \
            squashfs-tools tesseract-ocr tesseract-ocr-eng \
            redis-tools default-mysql-client postgresql-client php-cli \
            default-jdk-headless openvpn openssl \
        && break || { echo "apt attempt $i failed; retry"; sleep 12; }; \
    done; rm -rf /var/lib/apt/lists/*

RUN set -eux; apt-get update || true; \
    for pkg in jadx apktool aapt apksigner zipalign adb dex2jar; do \
        for i in 1 2 3; do apt-get install -y --no-install-recommends "$pkg" && break || sleep 6; done \
        || echo "mobile pkg skipped: $pkg"; \
    done; rm -rf /var/lib/apt/lists/* || true

RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
        -o Acquire::Retries=1 -o Acquire::http::Timeout=20 seclists \
    || echo "seclists apt skipped (using direct-wget essentials)"; rm -rf /var/lib/apt/lists/* || true; \
    mkdir -p /usr/share/wordlists/api; \
    B=https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content; \
    for f in common.txt raft-medium-directories.txt raft-medium-files.txt burp-parameter-names.txt; do \
        [ -s "/usr/share/wordlists/$f" ] || for i in 1 2 3; do wget -q -O "/usr/share/wordlists/$f" "$B/$f" && break || sleep 4; done; done; \
    [ -s /usr/share/wordlists/api/api-endpoints.txt ] || wget -q -O /usr/share/wordlists/api/api-endpoints.txt "$B/api/api-endpoints.txt" || true; \
    [ -e /usr/share/seclists/Discovery/Web-Content ] || { mkdir -p /usr/share/seclists/Discovery && ln -sfn /usr/share/wordlists /usr/share/seclists/Discovery/Web-Content; }; \
    WL=$(wc -l < /usr/share/wordlists/raft-medium-directories.txt 2>/dev/null || echo 0); echo "wordlists: raft-dirs=${WL} lines"; \
    [ "${WL}" -gt 100 ] || echo "!!! WARNING wordlists EMPTY — dir brute-forcing crippled"

RUN set -eux; arch="$(uname -m)"; case "$arch" in x86_64) NA=x64;; aarch64|arm64) NA=arm64;; *) NA=x64;; esac; \
    wget -q -O /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${NA}.tar.xz"; \
    tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1; rm -f /tmp/node.tar.xz; \
    node --version; npm install -g @anthropic-ai/claude-code; claude --version || true

COPY requirements.txt /app/requirements.txt
RUN pip3 install --break-system-packages -r /app/requirements.txt \
    && (pip3 install --break-system-packages tsec-benchmark || echo "tsec-benchmark not on index; platform provides it")
RUN pip3 install --break-system-packages \
        pwntools pycryptodome sympy gmpy2 z3-solver impacket boto3 awscli beautifulsoup4 requests \
    || echo "offensive libs partially skipped"
RUN pip3 install --break-system-packages \
        capstone unicorn numpy scipy lxml scapy pillow pyasn1 pefile xdis dnfile python-registry regipy \
        web3 eth-account pyevmasm psycopg2-binary \
    || echo "universal py libs partially skipped"
RUN pip3 install --break-system-packages androguard frida-tools objection \
    || echo "mobile py libs partially skipped (static path still works)"
RUN pip3 install --break-system-packages semgrep bandit || echo "semgrep/bandit skipped"
RUN pip3 install --break-system-packages cysignals fpylll || echo "fpylll skipped (lattice)"
RUN pip3 install --break-system-packages angr || echo "angr skipped (z3 covers most)"
RUN pip3 install --break-system-packages volatility3 mitmproxy || echo "volatility3/mitmproxy skipped"
RUN pip3 install --break-system-packages slither-analyzer py-solc-x || echo "slither/solcx skipped"
RUN gem sources --add https://mirrors.ustc.edu.cn/rubygems/ --remove https://rubygems.org/ >/dev/null 2>&1 || true; \
    gem sources -l; \
    gem install one_gadget seccomp-tools 2>/dev/null || echo "one_gadget/seccomp-tools skipped"
RUN gem install zsteg --no-document 2>/dev/null || echo "zsteg skipped"

RUN set -eux; mkdir -p /opt/tools; \
    (for U in "https://github.com/Giotino/stegsolve/releases/download/v1.4/StegSolve-1.4.jar" \
              "https://gh-proxy.com/https://github.com/Giotino/stegsolve/releases/download/v1.4/StegSolve-1.4.jar" \
              "http://www.caesum.com/handbook/Stegsolve.jar"; do \
        wget -q -T 15 -O /opt/tools/stegsolve.jar "$U" && [ -s /opt/tools/stegsolve.jar ] && break || rm -f /opt/tools/stegsolve.jar; done; \
     [ -s /opt/tools/stegsolve.jar ] && printf '#!/bin/sh\nexec java -jar /opt/tools/stegsolve.jar "$@"\n' > /usr/local/bin/stegsolve \
       && chmod +x /usr/local/bin/stegsolve) || echo "stegsolve skipped"; \
    (curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
      && bash /tmp/dotnet-install.sh --channel 8.0 --install-dir /usr/share/dotnet >/dev/null \
      && ln -sf /usr/share/dotnet/dotnet /usr/local/bin/dotnet \
      && DOTNET_ROOT=/usr/share/dotnet dotnet tool install --global ilspycmd --version 8.2.0.7535 \
      && ln -sf /root/.dotnet/tools/ilspycmd /usr/local/bin/ilspycmd \
      && rm -f /tmp/dotnet-install.sh) || echo "dotnet/ilspycmd skipped (~220MB, needs network)"
ENV DOTNET_ROOT=/usr/share/dotnet

RUN set -eux; arch="$(uname -m)"; case "$arch" in x86_64) GA=amd64;; aarch64|arm64) GA=arm64;; *) GA=amd64;; esac; \
    mkdir -p /opt/tools; \
    (cv=1.10.1; for i in 1 2 3; do wget -q -O /tmp/chisel.gz "https://github.com/jpillora/chisel/releases/download/v${cv}/chisel_${cv}_linux_${GA}.gz" \
        && gunzip -c /tmp/chisel.gz > /usr/local/bin/chisel && chmod +x /usr/local/bin/chisel && rm -f /tmp/chisel.gz && break || sleep 3; done; command -v chisel) || echo "chisel skipped"; \
    (cf=2.0.5; for U in "https://github.com/BishopFox/cloudfox/releases/download/v${cf}/cloudfox-linux-${GA}.zip" "https://gh-proxy.com/https://github.com/BishopFox/cloudfox/releases/download/v${cf}/cloudfox-linux-${GA}.zip"; do \
        for i in 1 2 3; do wget -q -O /tmp/cf.zip "$U" && unzip -q -o /tmp/cf.zip -d /tmp/cf && install -m0755 "$(find /tmp/cf -name cloudfox -type f | head -1)" /usr/local/bin/cloudfox && rm -rf /tmp/cf.zip /tmp/cf && break 2 || { rm -rf /tmp/cf.zip /tmp/cf; sleep 3; }; done; done; command -v cloudfox) || echo "cloudfox skipped"; \
    (wget -q -O /opt/tools/ysoserial.jar "https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar") || echo "ysoserial skipped"; \
    (for U in "https://github.com/RandomRobbieBF/marshalsec-jar/raw/main/marshalsec-0.0.3-SNAPSHOT-all.jar" \
              "https://gh-proxy.com/https://github.com/RandomRobbieBF/marshalsec-jar/raw/main/marshalsec-0.0.3-SNAPSHOT-all.jar"; do \
        wget -q -O /opt/tools/marshalsec.jar "$U" && [ -s /opt/tools/marshalsec.jar ] && break || rm -f /opt/tools/marshalsec.jar; done; [ -s /opt/tools/marshalsec.jar ]) || echo "marshalsec skipped"; \
    (for U in "https://github.com/welk1n/JNDI-Injection-Exploit/releases/download/v1.0/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar" \
              "https://gh-proxy.com/https://github.com/welk1n/JNDI-Injection-Exploit/releases/download/v1.0/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar"; do \
        wget -q -O /opt/tools/JNDI-Injection-Exploit.jar "$U" && [ -s /opt/tools/JNDI-Injection-Exploit.jar ] && break || rm -f /opt/tools/JNDI-Injection-Exploit.jar; done; [ -s /opt/tools/JNDI-Injection-Exploit.jar ]) || echo "JNDI-Injection-Exploit skipped"; \
    (git clone --depth 1 https://github.com/ticarpi/jwt_tool /opt/tools/jwt_tool) || echo "jwt_tool skipped"; \
    (cd=v1.5.2; wget -q -O /usr/local/bin/cdk "https://github.com/cdk-team/CDK/releases/download/${cd}/cdk_linux_${GA}" && chmod +x /usr/local/bin/cdk) || echo "cdk skipped"; \
    (nv=3.11.1; for i in 1 2 3; do wget -q -O /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${nv}/nuclei_${nv}_linux_${GA}.zip" \
        && unzip -q -o /tmp/nuclei.zip -d /usr/local/bin nuclei && chmod +x /usr/local/bin/nuclei && rm -f /tmp/nuclei.zip && break || sleep 5; done; nuclei -version 2>&1 | head -1) || echo "nuclei binary skipped"; \
    (for i in 1 2 3; do nuclei -update-templates 2>&1 | tail -1 && break || sleep 8; done); \
    NT=$(find /root/nuclei-templates -name '*.yaml' 2>/dev/null | wc -l); echo "nuclei-templates: ${NT} yaml"; \
    [ "${NT}" -gt 3000 ] || echo "!!! WARNING nuclei-templates EMPTY/THIN (${NT}) — bake via docker cp or nuclei detects NOTHING"

RUN (wget -q -O /root/.gdbinit-gef.py https://raw.githubusercontent.com/hugsy/gef/main/gef.py \
      && echo "source /root/.gdbinit-gef.py" > /root/.gdbinit) || echo "gef skipped"
RUN (pip3 install --break-system-packages playwright && python3 -m playwright install --with-deps chromium) || echo "playwright/chromium skipped"

RUN set -eux; GV=11.2.1; GD=20241105; \
    ( for U in "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GV}_build/ghidra_${GV}_PUBLIC_${GD}.zip" \
               "https://gh-proxy.com/https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GV}_build/ghidra_${GV}_PUBLIC_${GD}.zip"; do \
        for i in 1 2 3; do wget -q -O /tmp/ghidra.zip "$U" && unzip -q -o /tmp/ghidra.zip -d /opt && break 2 || { rm -f /tmp/ghidra.zip; sleep 5; }; done; done; \
      mv /opt/ghidra_${GV}_PUBLIC /opt/ghidra && ln -sf /opt/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless && rm -f /tmp/ghidra.zip \
      && test -x /opt/ghidra/support/analyzeHeadless ) || echo "ghidra skipped (r2 fallback)"
RUN set -eux; arch="$(uname -m)"; case "$arch" in x86_64) GA=amd64;; aarch64|arm64) GA=arm64;; *) GA=amd64;; esac; \
    (gv=2.63.2; for U in "https://github.com/cli/cli/releases/download/v${gv}/gh_${gv}_linux_${GA}.tar.gz" \
        "https://gh-proxy.com/https://github.com/cli/cli/releases/download/v${gv}/gh_${gv}_linux_${GA}.tar.gz"; do \
        for i in 1 2 3; do wget -q -O /tmp/gh.tgz "$U" && tar -xzf /tmp/gh.tgz -C /tmp && install -m0755 "$(find /tmp -name gh -type f -path '*/bin/*'|head -1)" /usr/local/bin/gh && rm -rf /tmp/gh.tgz && break 2 || sleep 4; done; done; command -v gh) || echo "gh skipped"

RUN set -eux; arch="$(uname -m)"; case "$arch" in x86_64) FA=amd64;; aarch64|arm64) FA=arm64;; *) FA=amd64;; esac; \
    V=v1.7.1; TB="foundry_${V}_linux_${FA}.tar.gz"; \
    ( for U in "https://github.com/foundry-rs/foundry/releases/download/${V}/${TB}" \
               "https://gh-proxy.com/https://github.com/foundry-rs/foundry/releases/download/${V}/${TB}"; do \
        for i in 1 2 3; do wget -q -O /tmp/foundry.tgz "$U" && tar -tzf /tmp/foundry.tgz >/dev/null 2>&1 && break 2 || { rm -f /tmp/foundry.tgz; sleep 3; }; done; \
      done; \
      tar -xzf /tmp/foundry.tgz -C /usr/local/bin forge cast anvil && rm -f /tmp/foundry.tgz \
      && forge --version && cast --version ) || echo "foundry skipped (web3.py fallback)"

RUN for i in 1 2 3; do apt-get update && apt-get install -y --no-install-recommends -o Acquire::Retries=2 sqlmap && break || sleep 8; done; \
    command -v sqlmap || pip3 install --break-system-packages sqlmap || echo "sqlmap unavailable"; \
    rm -rf /var/lib/apt/lists/* || true
RUN (cf=2.0.5; command -v cloudfox || for U in "https://github.com/BishopFox/cloudfox/releases/download/v${cf}/cloudfox-linux-amd64.zip" "https://gh-proxy.com/https://github.com/BishopFox/cloudfox/releases/download/v${cf}/cloudfox-linux-amd64.zip"; do \
      for i in 1 2 3; do wget -q -O /tmp/cf.zip "$U" && unzip -q -o /tmp/cf.zip -d /tmp/cf && install -m0755 "$(find /tmp/cf -name cloudfox -type f|head -1)" /usr/local/bin/cloudfox && rm -rf /tmp/cf.zip /tmp/cf && break 2 || { rm -rf /tmp/cf.zip /tmp/cf; sleep 4; }; done; done; command -v cloudfox) || echo "cloudfox skipped (awscli/boto3 fallback)"

RUN pip3 install --break-system-packages rapidocr-onnxruntime onnxruntime opencv-python-headless \
    && python3 -c "from rapidocr_onnxruntime import RapidOCR; RapidOCR()" \
    || echo "rapidocr skipped (tesseract remains the OCR floor)"

RUN for i in 1 2 3; do apt-get update && apt-get install -y --no-install-recommends -o Acquire::Retries=2 cmake pkg-config && break || sleep 6; done; rm -rf /var/lib/apt/lists/* || true; \
    for p in pwntools pycryptodome sympy gmpy2 z3-solver impacket; do \
        python3 -c "import ${p%%-*}" 2>/dev/null || pip3 install --break-system-packages --retries 5 "$p" \
        || echo "gap-fill pip skipped: $p"; done; \
    python3 -c "import pwn" && echo "pwntools OK" || echo "!!! pwntools STILL missing"
RUN for i in 1 2 3; do npm install -g @anthropic-ai/claude-code@2.1.197 --include=optional --force && claude --version && break || { echo "claude reinstall attempt $i"; sleep 5; }; done; \
    claude --version && echo "claude native binary OK"

RUN [ -s /opt/tools/marshalsec.jar ] || for U in \
        "https://github.com/RandomRobbieBF/marshalsec-jar/raw/main/marshalsec-0.0.3-SNAPSHOT-all.jar" \
        "https://gh-proxy.com/https://github.com/RandomRobbieBF/marshalsec-jar/raw/main/marshalsec-0.0.3-SNAPSHOT-all.jar" \
        "https://ghproxy.net/https://github.com/RandomRobbieBF/marshalsec-jar/raw/main/marshalsec-0.0.3-SNAPSHOT-all.jar"; do \
        wget -q -O /opt/tools/marshalsec.jar "$U" && [ -s /opt/tools/marshalsec.jar ] && break || rm -f /opt/tools/marshalsec.jar; done; \
    if [ ! -s /opt/tools/marshalsec.jar ]; then \
        echo "marshalsec prebuilt mirrors failed -> building from source (needs JDK 8: it uses sun.rmi.* internals removed in JDK 9+ + a malformed zip64 dep jar the image's JDK21 rejects)"; \
        (apt-get update && apt-get install -y --no-install-recommends maven || true; rm -rf /var/lib/apt/lists/* || true); \
        for U in "https://api.adoptium.net/v3/binary/latest/8/ga/linux/x64/jdk/hotspot/normal/eclipse" \
                 "https://gh-proxy.com/https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u422-b05/OpenJDK8U-jdk_x64_linux_hotspot_8u422b05.tar.gz"; do \
            wget -q -O /tmp/jdk8.tgz "$U" && tar -tzf /tmp/jdk8.tgz >/dev/null 2>&1 && break || rm -f /tmp/jdk8.tgz; done; \
        mkdir -p /opt/jdk8 && tar -xzf /tmp/jdk8.tgz -C /opt/jdk8 --strip-components=1 && rm -f /tmp/jdk8.tgz; \
        for G in "https://gh-proxy.com/https://github.com/mbechler/marshalsec.git" \
                 "https://github.com/mbechler/marshalsec.git"; do \
            rm -rf /tmp/marshalsec; git clone --depth 1 "$G" /tmp/marshalsec && break || rm -rf /tmp/marshalsec; done; \
        (cd /tmp/marshalsec && JAVA_HOME=/opt/jdk8 PATH=/opt/jdk8/bin:$PATH \
            mvn -q -B -Dmaven.test.skip=true -Denforcer.skip=true clean package \
            && cp target/marshalsec-0.0.3-SNAPSHOT-all.jar /opt/tools/marshalsec.jar) || echo "marshalsec source build failed"; \
        rm -rf /tmp/marshalsec /root/.m2 /opt/jdk8; \
    fi; \
    [ -s /opt/tools/marshalsec.jar ] && echo "marshalsec OK" || echo "marshalsec still missing (ysoserial covers most)"

RUN command -v d2j-dex2jar.sh >/dev/null 2>&1 || { \
        for U in "https://github.com/pxb1988/dex2jar/releases/download/v2.4/dex-tools-v2.4.zip" \
                 "https://gh-proxy.com/https://github.com/pxb1988/dex2jar/releases/download/v2.4/dex-tools-v2.4.zip"; do \
            wget -q -O /tmp/d2j.zip "$U" && unzip -q -o /tmp/d2j.zip -d /opt && break || rm -f /tmp/d2j.zip; done; \
        D=$(find /opt -maxdepth 1 -type d -name 'dex-tools-*' | head -1); \
        if [ -n "$D" ]; then chmod +x "$D"/*.sh 2>/dev/null || true; \
            for s in "$D"/d2j-*.sh; do [ -f "$s" ] && ln -sf "$s" /usr/local/bin/"$(basename "$s")"; done; fi; \
        rm -f /tmp/d2j.zip; }; \
    command -v d2j-dex2jar.sh >/dev/null 2>&1 && echo "dex2jar OK" || echo "dex2jar still missing (jadx/apktool cover mobile RE)"

ARG KB_MARCIO=0
ARG KB_TRICKEST=0
RUN set -eux; mkdir -p /opt/kb; \
    clone_kb() { dst="$1"; repo="$2"; min="$3"; \
        for U in "https://github.com/${repo}.git" "https://gh-proxy.com/https://github.com/${repo}.git"; do \
            for i in 1 2 3; do rm -rf "/opt/kb/${dst}"; git clone --depth 1 "$U" "/opt/kb/${dst}" && break 2 || sleep 5; done; \
        done; \
        rm -rf "/opt/kb/${dst}/.git" 2>/dev/null || true; \
        n=$(find "/opt/kb/${dst}" -type f 2>/dev/null | wc -l); echo "kb ${dst}: ${n} files"; \
        [ "${n}" -gt "${min}" ] && return 0 || { echo "!!! kb ${dst} EMPTY/THIN (${n} <= ${min})"; return 1; }; }; \
    kb_fail=""; \
    clone_kb vulhub               vulhub/vulhub                 500 || kb_fail="$kb_fail vulhub"; \
    clone_kb PayloadsAllTheThings swisskyrepo/PayloadsAllTheThings 400 || kb_fail="$kb_fail PAT"; \
    clone_kb awesome-poc          Threekiii/Awesome-POC         300 || kb_fail="$kb_fail awesome-poc"; \
    clone_kb exphub               zhzyker/exphub                 60 || kb_fail="$kb_fail exphub"; \
    [ "${KB_MARCIO}" = "1" ] && clone_kb marcio-cve 0xMarcio/cve 200 || echo "marcio-cve skipped (size-capped platform build; ARG KB_MARCIO=1 to include)"; \
    [ "${KB_TRICKEST}" = "1" ] && clone_kb trickest-cve trickest/cve 5000 || echo "trickest-cve skipped (size-capped platform build; ARG KB_TRICKEST=1 to include)"; \
    if [ -n "$kb_fail" ]; then echo "!!! BUILD FAILED: kb corpora missing:${kb_fail}"; exit 1; fi; \
    find /opt/kb -type f ! -name INDEX.txt \
        \( -name '*.md' -o -name '*.py' -o -name '*.txt' -o -name '*.yaml' -o -name '*.json' \) \
        | sed 's|^/opt/kb/||' | sort > /tmp/kb_index.txt; \
    mv /tmp/kb_index.txt /opt/kb/INDEX.txt; \
    echo "kb INDEX: $(wc -l < /opt/kb/INDEX.txt) knowledge files"

COPY hxbai /app/hxbai
COPY drivers /app/drivers
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

RUN mkdir -p /opt/tools && ln -sf /app/hxbai/knowledge/cve-quick.json /opt/tools/cve-quick.json \
    && cd /app && python3 -m hxbai.knowledge.check_cve_quick

RUN set -eu; log=/opt/tools/BUILD_SELFCHECK.txt; : > "$log"; missing_p0=""; \
    p0_bin="node python3 curl wget git jq rg nmap ffuf gobuster sqlmap nikto whatweb tshark binwalk foremost exiftool steghide xxd zip unzip file gdb radare2 objdump strings hydra john socat ncat proxychains4 tmux openvpn java unsquashfs tesseract redis-cli psql php nc ssh sshpass"; \
    opt_bin="jadx apktool aapt apksigner zipalign adb d2j-dex2jar.sh mysql mariadb hashcat chisel nuclei cloudfox cdk gh analyzeHeadless forge cast anvil gdb-multiarch tcpdump masscan zsteg stegsolve mcs mono ilspycmd"; \
    for b in $p0_bin; do if command -v "$b" >/dev/null 2>&1; then echo "P0 bin OK   $b" >>"$log"; else echo "P0 bin MISS $b" >>"$log"; missing_p0="$missing_p0 $b"; fi; done; \
    if claude --version >/dev/null 2>&1; then echo "P0 claude OK ($(claude --version 2>&1 | head -1))" >>"$log"; else echo "P0 claude MISS (native binary broken -> solver dead)" >>"$log"; missing_p0="$missing_p0 claude"; fi; \
    for b in $opt_bin; do if command -v "$b" >/dev/null 2>&1; then echo "opt bin OK  $b" >>"$log"; else echo "opt bin warn $b (degraded)" >>"$log"; fi; done; \
    for j in ysoserial marshalsec JNDI-Injection-Exploit; do if [ -s "/opt/tools/$j.jar" ]; then echo "jar OK   $j" >>"$log"; else echo "jar warn $j (degraded)" >>"$log"; fi; done; \
    for m in Crypto z3 pwn web3 PIL scapy lxml scipy rapidocr_onnxruntime; do if python3 -c "import $m" >/dev/null 2>&1; then echo "py OK   $m" >>"$log"; else echo "py warn $m" >>"$log"; fi; done; \
    echo "--- cve-quick + entries ---" >>"$log"; (cd /app && python3 -m hxbai.knowledge.check_cve_quick) >>"$log" 2>&1 || true; \
    echo "--- kb corpora ---" >>"$log"; ls /opt/kb >>"$log" 2>&1 || true; \
    KB=$(wc -l < /opt/kb/INDEX.txt 2>/dev/null || echo 0); echo "kb INDEX: ${KB} files" >>"$log"; \
    [ "${KB}" -gt 2000 ] || echo "!!! WARNING kb INDEX THIN (${KB}) — offline PoC lookup degraded" >>"$log"; \
    echo "==== SELF-CHECK SUMMARY ====" >>"$log"; \
    if [ -n "$missing_p0" ]; then echo "P0 MISSING:$missing_p0" >>"$log"; cat "$log"; echo "!!! BUILD FAILED: P0 tools missing:$missing_p0"; exit 1; fi; \
    echo "ALL P0 PRESENT" >>"$log"; cat "$log"

WORKDIR /app
ENV HXBAI_WORKDIR=/tmp/hxbai-work IS_SANDBOX=1 TERM=xterm
ENTRYPOINT ["/app/entrypoint.sh"]
