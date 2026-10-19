# Sandbox escape — Lua

"Lua jail" = server runs your Lua via `load`/`loadstring`/`dofile` in a filtered `_ENV`. Interpreters offline: `lua5.4` (installed).

## Dangerous primitives
- **`os.execute("id")`, `os.getenv`, `io.popen("id"):read("*a")`, `io.open("/flag"):read("*a")`** — direct RCE / file read (often enough).
- **`load`/`loadstring`/`dofile`/`require`** — load more code.
- **`string.dump` / bytecode loading** — feed crafted Lua bytecode to `load` (LuaJIT/5.1 lets malformed bytecode escape sandboxes).
- **`debug` library** — `debug.getupvalue`/`setupvalue`/`getregistry`/`sethook`: reach out of the sandbox `_ENV`, read/replace upvalues (including the sandbox's own), or grab the real global table from the registry.
- **`coroutine`, metatables** — `getmetatable("").__index` reaches the `string` library; if strings' metatable isn't sandboxed you climb from a literal to `string` to more.

## Typical escapes
- **Recover globals**: even with a stripped `_ENV`, `("").__index` (string metatable) or `debug.getregistry()` often yields a path back to `os`/`io`.
- **Bytecode**: if `load(str, name, "b")` (binary mode) is allowed, craft bytecode that dereferences arbitrary memory / calls C functions (version-specific; test on `lua5.4`).
- **Blacklist bypass**: build function names from `string.char`/concatenation (`_G["o".."s"]`), index via `_G`/`_ENV`, use `rawget`.
- Simplest: if `io`/`os` survive, `io.open("/flag","r"):read("*a")`.

```lua
-- direct read
local f=io.open("/flag","r"); print(f:read("*a"))
-- via string metatable when _ENV is stripped
local mt = getmetatable("")            -- string library table
-- climb mt.__index to reach loaded libs
```

Recognition: `load`/`loadstring`/`setfenv`/`_ENV`, a table of allowed functions, redis/nginx `eval` (OpenResty), game scripting. Test escapes on local `lua5.4`; most sandboxes miss `debug`, string-metatable, or bytecode routes.
