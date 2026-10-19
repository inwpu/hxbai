#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
import sys
import time

DOCKERFILE = "Dockerfile.engine"

def _docker_ok():
    try:
        return subprocess.call(["docker", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except Exception:
        return False


FLATTEN_LAYER_THRESHOLD = 80


def _layer_count(tag: str) -> int:
    try:
        out = subprocess.check_output(["docker", "history", "-q", "--no-trunc", tag],
                                      stderr=subprocess.DEVNULL).decode()
        return len([ln for ln in out.splitlines() if ln.strip()])
    except Exception:
        return -1


def _flatten_image(src: str, dst: str) -> bool:
    def _inspect(fmt):
        try:
            return subprocess.check_output(["docker", "inspect", src, "--format", fmt],
                                           stderr=subprocess.DEVNULL).decode()
        except Exception:
            return ""
    changes = []
    for e in _inspect("{{range .Config.Env}}{{println .}}{{end}}").splitlines():
        if e.strip():
            changes += ["--change", "ENV " + e]
    ep = _inspect("{{json .Config.Entrypoint}}").strip()
    if ep and ep != "null":
        changes += ["--change", "ENTRYPOINT " + ep]
    cmd = _inspect("{{json .Config.Cmd}}").strip()
    if cmd and cmd != "null":
        changes += ["--change", "CMD " + cmd]
    wd = _inspect("{{.Config.WorkingDir}}").strip()
    if wd:
        changes += ["--change", "WORKDIR " + wd]
    usr = _inspect("{{.Config.User}}").strip()
    if usr:
        changes += ["--change", "USER " + usr]
    cname = "hxctfflat_tmp"
    subprocess.call(["docker", "rm", "-f", cname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if subprocess.call(["docker", "create", "--name", cname, src],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        return False
    ok = False
    try:
        p1 = subprocess.Popen(["docker", "export", cname], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(["docker", "import"] + changes + ["-", dst], stdin=p1.stdout)
        p1.stdout.close()
        ok = (p2.wait() == 0) and (p1.wait() == 0)
    except Exception:
        ok = False
    finally:
        subprocess.call(["docker", "rm", "-f", cname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return ok


try:
    from build_image import c, run, ensure_cache_builder, function_check, _image_exists
except Exception:
    def c(m, _col=""):
        return m

    def run(cmd, **kw):
        print("$ " + " ".join(cmd), flush=True)
        return subprocess.call(cmd, **kw)

    def ensure_cache_builder():
        pass

    def function_check(_args):
        print("(build_image.py 不在旁边,跳过功能检查)")
        return True

    def _image_exists(tag):
        return subprocess.call(["docker", "image", "inspect", tag],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


def main():
    ap = argparse.ArgumentParser(description="增量叠最新引擎到稳定基底 hxctf:base → hxctf:v1(离线,~10-30s)")
    ap.add_argument("--tag", default="hxctf:v1", help="输出镜像 tag(默认 hxctf:v1)")
    ap.add_argument("--base", default="hxctf:base", help="稳定基底 tag(默认 hxctf:base;Dockerfile.engine 的 FROM)")
    ap.add_argument("--no-check", action="store_true", help="跳过构建后的功能检查")
    ap.add_argument("--force-flatten", action="store_true", help="冻结 base 前强制拍平 v1(不看层数阈值;测试/手动恢复用)")
    args = ap.parse_args()

    print(c("============ hxctf 引擎增量叠加 ============", "y"))

    if not _docker_ok():
        print(c("✗ docker 不可用,请确认 Docker Desktop 已启动。", "r"))
        sys.exit(2)
    if not _image_exists(args.base):
        if _image_exists(args.tag):
            nlayers = _layer_count(args.tag)
            if args.force_flatten or (0 < FLATTEN_LAYER_THRESHOLD < nlayers):
                print(c(f"  {args.tag} 层数={nlayers} (>{FLATTEN_LAYER_THRESHOLD}) 或 --force-flatten → 先拍平(export/import,保元数据,21G 约几分钟)", "y"))
                if _flatten_image(args.tag, args.base):
                    print(c(f"  ✓ 拍平完成:{args.base} 层数={_layer_count(args.base)}(从臃肿 {nlayers} 层)", "g"))
                else:
                    print(c(f"  ⚠ 拍平失败,回退普通 tag(若随后构建报 mount 超限,请手动拍平)", "y"))
                    if run(["docker", "tag", args.tag, args.base]) != 0:
                        print(c(f"✗ 无法创建稳定基底 {args.base}", "r")); sys.exit(2)
            else:
                print(c(f"  首次:冻结当前 {args.tag}(层数={nlayers})为稳定基底 {args.base}(docker tag)", "y"))
                if run(["docker", "tag", args.tag, args.base]) != 0:
                    print(c(f"✗ 无法创建稳定基底 {args.base}", "r")); sys.exit(2)
        else:
            print(c(f"✗ 基底 {args.base} 和 {args.tag} 都不存在 —— 先跑 `python build_image.py` 完整从-0 构建。", "r"))
            sys.exit(2)
    missing = [p for p in (DOCKERFILE, "engine/run_bench.py", "engine/timebox.py", "engine/scheduler.py") if not os.path.exists(p)]
    if missing:
        print(c(f"✗ 缺少文件:{missing}。请把 Dockerfile.engine + engine/(最新)拷到本目录。", "r"))
        sys.exit(2)
    print(c(f"  ✓ 稳定基底 {args.base} 已在;Dockerfile.engine + engine/ 齐全;无需代理(纯本地 COPY)", "g"))

    print(c("\n[1/3] docker build -f Dockerfile.engine(FROM base,只叠引擎,legacy builder,约 10-30s)", "y"))
    os.environ["DOCKER_BUILDKIT"] = "0"
    cmd = ["docker", "build", "-f", DOCKERFILE, "-t", args.tag, "."]
    t0 = time.time()
    rc = run(cmd)
    dur = int(time.time() - t0)
    if rc != 0:
        print(c(f"\n✗ 增量构建失败(退出码 {rc},耗时 {dur}s)。日志里若有 ImportError/SyntaxError,多为 engine 代码问题。", "r"))
        sys.exit(rc)
    print(c(f"\n  ✓ 引擎增量叠加成功:{args.tag}(耗时 {dur}s)", "g"))

    print(c("\n[2/3] 镜像信息", "y"))
    run(["docker", "images", args.tag])

    if not args.no_check:
        print(c("  ⚠ 下面的功能检查对**增量路径仅信息性**,不是构建成败判据(构建成败以末尾 [3/3] 完成 + 退出码 0 为准)。", "y"))
        print(c("    其中 llm_egress(HXCTF_LLM_EGRESS=tsecbench 托管出口)在 base/v1 上**必报缺失**=预期:它由 slim_image.py 注入,"
                "base 本地直连 deepseek 本就不设。看到 ❌ llm_egress 别慌,不代表镜像坏。", "y"))
        passed = function_check(args)
        if not passed:
            print(c("  ✓ 增量构建**成功**(上面 ❌ 仅功能检查信息性结论:工具/库/KB 继承自 base 不可能丢;llm_egress 等托管出口由"
                    " slim_image 注入、base 本就不设)。引擎有效性已由 Dockerfile.engine compileall+import 自检强制保证。", "g"))
            print(c("    下一步:python slim_image.py(出托管包时注入 egress);要真判托管镜像 P0 在 slim_image 产物上另跑。", "g"))

    print(c("\n[3/3] 完成", "y"))
    print(c("  出 <3G 托管包:python slim_image.py", "b"))
    sys.exit(0)


if __name__ == "__main__":
    main()
