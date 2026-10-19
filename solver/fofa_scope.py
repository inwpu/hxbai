#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.parse
import urllib.request

TENCENT_DOMAINS = (
    "tencent.com", "qcloud.com", "qq.com", "qcloud.net", "tencentcs.com",
    "tencent-cloud.com", "tencentcloudapi.com", "myqcloud.com", "tenclass.com",
    "weixin.qq.com", "wechat.com", "tim.qq.com", "meeting.tencent.com",
)

PRODUCTS: dict[str, list[str]] = {
    "腾讯会议": [
        'domain="meeting.tencent.com"',
        'title="腾讯会议官方"',
        'body="meeting.tencent.com" && title!="404"',
    ],
    "腾讯元宝": [
        'domain="yuanbao.tencent.com"',
        'title="腾讯元宝"',
        'body="yuanbao.tencent.com"',
    ],
    "腾讯文档": [
        'domain="docs.qq.com"',
        'title="腾讯文档" && domain="qq.com"',
    ],
    "电脑管家": [
        'domain="guanjia.qq.com"',
        'title="电脑管家" && domain="qq.com"',
    ],
    "腾讯云": [
        'domain="cloud.tencent.com" && status_code="200"',
        'domain="qcloud.com" && status_code="200"',
    ],
    "腾讯地图": [
        'domain="map.qq.com"',
        'title="腾讯地图" && domain="qq.com"',
    ],
}

_CALL_INTERVAL_S = 66.0
_last_call = [0.0]


def _throttle():
    wait = _CALL_INTERVAL_S - (time.time() - _last_call[0])
    if wait > 0:
        print(f"[.] 节流等待 {wait:.0f}s(FOFA 限速)", file=sys.stderr)
        time.sleep(wait)
    _last_call[0] = time.time()


def fofa_search(key: str, query: str, size: int = 100, page: int = 1,
                fields: str = "host,ip,port,protocol,title,domain,icp,cert,server,country,city") -> dict:
    qb = base64.b64encode(query.encode()).decode()
    params = {"key": key, "qbase64": qb, "size": size, "fields": fields, "page": page}
    for attempt in range(3):
        _throttle()
        url = "https://fofa.info/api/v1/search/all?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 2:
                back = 70 * (attempt + 1)
                print(f"[!] 429 限速,退避 {back}s(第 {attempt+1} 次)", file=sys.stderr)
                time.sleep(back)
                _last_call[0] = time.time()
                continue
            return {"error": True, "errmsg": f"HTTP {e.code}"}
        except Exception as e:
            return {"error": True, "errmsg": repr(e)[:100]}
    return {"error": True, "errmsg": "429 三次退避仍失败"}


_FIELD_KEYS = ("host", "ip", "port", "protocol", "title", "domain", "icp", "cert",
               "server", "country", "city")


def _row_dict(row) -> dict:
    if isinstance(row, dict):
        return row
    return dict(zip(_FIELD_KEYS, list(row) + [""] * 12))


def classify(row: dict) -> tuple[str, str] | None:
    dom = (row.get("domain") or "").lower().strip(".")
    host = (row.get("host") or "").lower()
    icp = row.get("icp") or ""
    title = row.get("title") or ""
    for d in TENCENT_DOMAINS:
        if dom == d or dom.endswith("." + d) or host.endswith(d):
            return "A", f"domain={dom or host}"
    if "腾讯" in icp:
        return "B", f"icp={icp[:40]}"
    has_tencent_mark = any(m in (title + str(row.get("cert") or "")).lower()
                           for m in ("tencent", "腾讯", "qcloud"))
    if has_tencent_mark and row.get("ip") and not dom:
        return "C", f"title={title[:40]}"
    return None


def collect(key: str, products: list[str], limit: int, keep_weak: bool) -> tuple[list[dict], int]:
    out, seen, dropped = [], set(), 0
    for prod in products:
        for q in PRODUCTS.get(prod, [f'title="{prod}"']):
            d = fofa_search(key, q, size=min(100, max(limit * 3, 30)))
            if d.get("error") not in (False, 0, None):
                print(f"[!] {prod} | {q} 失败: {d.get('errmsg')}", file=sys.stderr)
                continue
            rows = d.get("results") or []
            print(f"[+] {prod} | {q} -> {len(rows)} 条(总匹配 {d.get('size', '?')})",
                  file=sys.stderr)
            for raw in rows:
                row = _row_dict(raw)
                host = (row.get("host") or "").strip()
                if not host or host in seen:
                    continue
                cls = classify(row)
                if not cls:
                    dropped += 1
                    continue
                grade, ev = cls
                if grade == "C" and not keep_weak:
                    dropped += 1
                    continue
                seen.add(host)
                url = host if "://" in host else f"{row.get('protocol') or 'https'}://{host}"
                out.append({"url": url, "host": host, "product": prod,
                            "grade": grade, "evidence": ev})
                if len(out) >= limit:
                    return out, dropped
    return out, dropped


def main() -> int:
    ap = argparse.ArgumentParser(description="FOFA→腾讯资产确认→finding-live 目标清单")
    ap.add_argument("--key", default=os.environ.get("FOFA_KEY", ""))
    ap.add_argument("--product", action="append", choices=sorted(PRODUCTS))
    ap.add_argument("--all", action="store_true", help="全部核心产品")
    ap.add_argument("--limit", type=int, default=15)
    ap.add_argument("--weak", action="store_true", help="保留 C 级弱证资产(默认弃)")
    ap.add_argument("--out", default="/out/tscope.json")
    args = ap.parse_args()
    if not args.key:
        print("需要 FOFA_KEY env 或 --key", file=sys.stderr)
        return 1
    products = args.product or (sorted(PRODUCTS) if args.all else ["腾讯会议"])
    n_q = sum(len(PRODUCTS.get(p, [""])) for p in products)
    print(f"[i] {len(products)} 产品 / {n_q} 查询 / 节流 { _CALL_INTERVAL_S:.0f}s/次 → 约 {n_q * _CALL_INTERVAL_S / 60:.0f} 分钟",
          file=sys.stderr)
    targets, dropped = collect(args.key, products, args.limit, args.weak)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(targets, f, ensure_ascii=False, indent=1)
    print(f"\n共 {len(targets)} 个确认腾讯资产(A/B 级 {sum(1 for t in targets if t['grade'] in 'AB')},"
          f"弃 {dropped} 范围外/弱证)→ {args.out}", file=sys.stderr)
    for t in targets:
        print(f"  [{t['grade']}] {t['url']}  ({t['product']} | {t['evidence'][:40]})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
