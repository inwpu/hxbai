# Sandbox escape — Python pickle / marshal VM

Generalizes the `pyjail` family to the **serialization** layer. `pickle.loads`/`marshal.loads`/`__reduce__`/`find_class` are code-execution primitives. This page is technique, not a per-challenge answer.

## pickle is a stack VM — you write opcodes
Unpickling executes a bytecode program. Key opcodes: `GLOBAL (c)` push `module.attr`, `REDUCE (R)` call `callable(args)`, `BUILD (b)`, `INST/OBJ`, `NEWOBJ`, `STACK_GLOBAL`, `PERSID/BINPERSID` (invoke `persistent_load`), `MARK/TUPLE/DICT/SETITEMS`. Anything importable is reachable via `GLOBAL`, and `REDUCE` calls it.

Minimal RCE payload (when `pickle.loads` is fed attacker bytes with a permissive `find_class`):
```python
import pickle, os
class E:
    def __reduce__(self): return (os.system, ("id",))
payload = pickle.dumps(E())          # -> unpickling runs os.system("id")
```

## Restricted unpicklers (the "jail")
Challenges subclass `pickle.Unpickler` and override `find_class(module, name)` to allow-list. Escapes:
- **Allowed callables are enough**: `builtins.getattr`, `builtins.eval`/`exec`, `builtins.__import__`, `builtins.setattr`, `dict.update`, `functools.reduce`, `operator.*` — any one often chains to RCE. If `getattr` + almost anything is allowed, walk to `os`/`subprocess`.
- **Hijack `find_class` itself**: overwrite the unpickler's own `find_class` (or `persistent_load`) via `BUILD`/`__dict__` `SETITEMS` so subsequent `GLOBAL` opcodes go through *your* resolver (the classic "set `up.__getattribute__ = __main__.__getattribute__`" trick). Then you control class resolution and reach forbidden modules.
- **`persistent_load`**: if defined, `PERSID` calls it with your string — abuse if it does anything reflective.
- **Reach builtins from an allowed class**: `().__class__.__bases__[0].__subclasses__()` to find a class whose module gives `os`/`subprocess`/`__import__` (same subclass-walk as pyjail, but expressed as pickle opcodes).
- **Blocked `R`/`REDUCE`**: use `INST`/`OBJ`/`BUILD` to instantiate and set state without `REDUCE`; `NEWOBJ` + `BUILD` can call `__setstate__`.

Craft opcodes by hand (`pickletools.dis` to read/verify), or with the **`pickora`** compiler (installed offline): it compiles Python-like source to pickle bytecode, so you write the escape in pseudo-Python and get opcodes.
```bash
python3 -c "import pickletools,sys;pickletools.dis(open(sys.argv[1],'rb').read())" payload.pkl
```

## marshal
`marshal.loads` deserializes **code objects** — feed a crafted `code` object (or `types.FunctionType(marshal.loads(bytes), globals())()`) to run arbitrary bytecode. Version-sensitive (magic per Python version); build the code object on the *same* interpreter version as the target.

## Recognition & first moves
- See `pickle.loads`, `Unpickler`, `__reduce__`, `find_class`, `marshal.loads`, `PERSID` in the source.
- Read the exact allow-list in `find_class`. Enumerate what's permitted, then find the shortest chain from a permitted name to code execution.
- If nothing is obviously permitted, target the unpickler object's own attributes (`find_class`, `persistent_load`, `__reduce__` policies) via `BUILD`.
