-- TSG：类型化状态图（方案 §3.1）。每题一库、追加式、事件溯源。
-- 设计：一切写操作先产事件（events 表 + _events.jsonl），节点/边/finding 是事件的物化视图，
--       可由 events 重放重建（Acceptance v1b#1 的 replay==snapshot 判据）。
-- schema 一次建对（墨菲：改一次最痛）：新增题型/资产类型只加 type 取值，不改表结构。

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ── 事件流（唯一真相源；节点/边/finding 都是它的物化）──────────────────
CREATE TABLE IF NOT EXISTS events (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,   -- 全序（重放按此序）
  ts         REAL    NOT NULL,
  kind       TEXT    NOT NULL,   -- node_upsert/edge_add/finding_upsert/evidence_add/
                                 -- decision/observation/adjudication/budget/scope/session
  actor      TEXT    NOT NULL,   -- decide / execute / adjudicate / control / scope / oracle
  payload    TEXT    NOT NULL    -- JSON;物化逻辑据此重建下面各表
);

-- ── 节点（资产层 + 任务层，类型化）────────────────────────────────────
-- type: host/service/endpoint/credential/capability/foothold/vuln/artifact/
--       goal/subgoal/step/hypothesis/claim/insight/deadend
-- state: 由 type 决定语义（如 subgoal: open/active/achieved/refuted/abandoned）
CREATE TABLE IF NOT EXISTS nodes (
  id          TEXT PRIMARY KEY,          -- 稳定 id
  type        TEXT NOT NULL,
  ukey        TEXT,                       -- 去重键（同 type+ukey 视为同一实体，upsert 合并）
  title       TEXT,
  state       TEXT,
  confidence  REAL DEFAULT 0.5,           -- 信念置信 0..1（POMDP belief）
  freshness   REAL,                       -- 最近验证时刻（指数衰减用）
  provenance  TEXT,                       -- 事实来源通道（observation/inferred/…）
  verified    INTEGER DEFAULT 0,          -- 是否经机检验证（L0/L1）；未验证不得被 Decide 盖楼
  extra       TEXT DEFAULT '{}',          -- JSON：type 特有字段（如 capability 的 payload）
  created_ts  REAL NOT NULL,
  updated_ts  REAL NOT NULL,
  UNIQUE(type, ukey)
);
CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(type);

-- ── 边（关系）─────────────────────────────────────────────────────────
-- rel: exposes/runs_on/authenticates_to/enables/contradicts/superseded_by/
--      produced_by/serves(step→subgoal)/pivots_to/affects(vuln→asset)
CREATE TABLE IF NOT EXISTS edges (
  id       TEXT PRIMARY KEY,
  src      TEXT NOT NULL REFERENCES nodes(id),
  dst      TEXT NOT NULL REFERENCES nodes(id),
  rel      TEXT NOT NULL,
  extra    TEXT DEFAULT '{}',
  created_ts REAL NOT NULL,
  UNIQUE(src, dst, rel)
);
CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst);

-- ── 证据（可寻址存证，喂 L1）方案 §3.3/§4.1 ──────────────────────────
CREATE TABLE IF NOT EXISTS evidence (
  id         TEXT PRIMARY KEY,
  node_id    TEXT REFERENCES nodes(id),
  kind       TEXT NOT NULL,               -- tool_result/pov_replay/sentinel/oob/crash
  content    TEXT,                         -- 观察原文（工具真实回显；断言不进这）
  sha256     TEXT NOT NULL,               -- 内容寻址
  triple     TEXT DEFAULT '{}',           -- 可重放三元组(env/input/criterion)哈希
  created_ts REAL NOT NULL
);

-- ── Finding：漏洞发现记录（提炼 ARTEX 方法 + 我们的机检/计算强化）─────
-- 分类：vulnclass 自由标签 + CWE/OWASP 软背骨（聚合用，不强制枚举）
-- 等级：severity 由 impact×exploitability 计算（severity_basis 可审计），不自评
-- 生命周期：status 处置态
-- 铁律：verified=1（经 L1 机检）才算 finding；否则只是 candidate/hypothesis
CREATE TABLE IF NOT EXISTS findings (
  id             TEXT PRIMARY KEY,
  node_id        TEXT REFERENCES nodes(id),   -- 关联的 vuln/claim 节点
  vulnclass      TEXT NOT NULL,               -- 自由文本类（如 "SQLi","SSRF"）
  cwe            TEXT,                         -- 软背骨锚点（如 "CWE-89"）
  owasp          TEXT,                         -- 如 "A03:2021-Injection"
  severity       TEXT NOT NULL,               -- critical/high/medium/low/info
  severity_basis TEXT DEFAULT '{}',           -- JSON：{impact,exploitability,rule} 计算依据
  status         TEXT NOT NULL DEFAULT 'candidate',
                 -- candidate → verifying → confirmed / false_positive / duplicate / superseded
                 --   (企业 finding-mode 追加 resolved / risk_accepted)
  verified       INTEGER NOT NULL DEFAULT 0,  -- L1 机检通过？未过不得对外称"漏洞"
  summary        TEXT,
  evidence_ref   TEXT REFERENCES evidence(id),-- 指向可复现证据
  asset_ids      TEXT DEFAULT '[]',           -- JSON 数组：受影响资产节点 id
  report_md      TEXT,                         -- 详细报告（Markdown，可后补）
  verdict        TEXT,                         -- 五态判决(VULN 块A/A3):CONFIRMED/NOT_REPRODUCED/BLOCKED/INCONCLUSIVE/ERROR
                 --   (1011 DB 同步:G3a 判决曾只落 verified bool,BLOCKED/INCONCLUSIVE 语义丢失)
  tier           TEXT,                         -- 交付优先级(块F1 验证轴):P0/P1+/P1/P2/low-capped
  risk_meta      TEXT DEFAULT '{}',            -- JSON:{layer,epss,epss_percentile,kev}(块F2 enrich 产物)
  extra          TEXT DEFAULT '{}',            -- JSON:申报佐证链元数据(§15.21 F2):session_id/wave——
                 --   finding 确认时的引擎会话锚点(S1/S2/S3 申报溯源;loop._register_finding 写入)
  created_ts     REAL NOT NULL,
  updated_ts     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

-- ── 元信息 ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT
);
