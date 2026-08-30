# LuaVM Obfuscator

VM-based Lua 5.1 obfuscator. It compiles source with a Lua 5.1 compiler, embeds a custom bytecode format, and ships a randomized interpreter. It is an IP-obfuscation layer, not a way to keep secrets on a client.

## How it works

Every build:
- **Shuffles all 38 Lua opcodes** into a random permutation (so `MOVE` might be opcode `23` this build, `7` next build)
- **Triple-pass LCG-XOR encrypts** every instruction array — forward → backward → forward with different key widths each pass
- **Encrypts every string constant** individually with its own random key
- **Randomizes all VM variable names** to 15-character alphanumeric strings
- **CRC32 integrity check** — tampered bytecode kills the script at startup
- **Anti-tamper probes** — checks for hooked globals and debug injection
- **Per-closure isolation** — each function gets its own encrypted code block and constant table

## Requirements

- Python 3.9+
- `luac` (Lua 5.1 compiler) in PATH
  - Windows: `choco install lua` or grab from [lua.org](https://www.lua.org/download.html)
  - Linux: `sudo apt install lua5.1`
  - Mac: `brew install lua@5.1`

Input must be **Lua 5.1-compatible** (strip Luau type annotations before obfuscating).

## Targets

The input compiler is always standard Lua 5.1. Select the output runtime explicitly:

- `--target luau` (default): Roblox/Luau output. Uses Luau features such as `continue`, `bit32`, and `string.unpack`.
- `--target lua51`: standard Lua 5.1 output. Includes pure-Lua bit and unpack compatibility helpers; it does not require Luau syntax.

`--double` is currently available only with `--target lua51`, because that stage must be compiled again by the Lua 5.1 compiler.

## Usage

```bash
# Basic
python obf.py script.lua

# Custom output path
python obf.py script.lua output.lua

# Deterministic build (same seed = same output every time)
python obf.py script.lua --seed 1337

# Double-wrapped (VM inside VM — maximum protection)
python obf.py script.lua --double

# Standard Lua 5.1 output
python obf.py script.lua output.lua --target lua51

# Enable the optional, intrusive debug-hook probe only in a controlled runtime
python obf.py script.lua --anti-debug
```

## Output size

| Mode       | Typical overhead |
|------------|-----------------|
| Single VM  | ~5–15× source   |
| Double VM  | ~25–60× source  |

The overhead comes from embedding the VM interpreter + encrypted bytecode.

## Layers of protection

| Layer | What it does |
|---|---|
| Opcode remapping | All 38 opcodes get new random values — static disassemblers produce garbage |
| Triple-pass XOR | Forward + backward + forward encryption with LCG key stream |
| Per-string keys | Every string constant has its own independent random key |
| CRC32 check | Any modification to the bytecode array crashes the script |
| Name randomization | 15-char random names for every VM function and variable |
| Opaque predicates | Always-true conditions confuse static control flow analysis |
| Double VM | `--double` wraps the output in a second independent VM layer |

## Notes

- Does **not** support Luau-specific syntax (type annotations, `::label::`, etc.) — strip those first
- The obfuscated output is slower than native Lua (VM overhead) — expected for this protection level
- Use `--seed` for reproducible builds in CI
- The output has to decode itself at runtime. Do not embed credentials, private keys, authorization rules, or high-value business logic that must remain secret. Keep those server-side and use short-lived server-issued authorization where appropriate.
- The CRC detects accidental output corruption. It is not a cryptographic tamper barrier, because a determined client-side attacker can modify both code and its check.

## Web service safeguards

The Flask service binds to `127.0.0.1` by default. If you expose it, set `MWP_API_TOKEN` and put it behind TLS plus rate limiting. It supports these environment limits: `MWP_MAX_SOURCE_BYTES` (default 200000), `MWP_MAX_OUTPUT_BYTES` (4000000), and `MWP_MAX_CONCURRENT_JOBS` (2). Use `MWP_HOST` only when an external bind is intentional.

## Tests

Run `python -B test_obf.py` to exercise parser, target, serialization, and key-isolation checks. When `lua` and a Lua 5.1 `luac` are on `PATH`, the suite also runs the same closure, vararg, loop, metamethod, multi-return, and UTF-8 script both directly and through the Lua 5.1 output runtime.

## Performance gate

Run `python benchmark.py test.obf.lua --runtime luau --runs 100`. It prints median and p95 startup time and exits with failure when p95 exceeds 1000 ms (override with `--limit-ms`). Profile on the same hardware and runtime you ship; output startup is runtime-dependent.

## Website integration

The obfuscator is a self-contained Python script — call it from your backend:

```python
import subprocess, tempfile, os

def obfuscate(lua_source: str, seed: int = None) -> str:
    with tempfile.NamedTemporaryFile(suffix='.lua', delete=False, mode='w') as f:
        f.write(lua_source); tmp_in = f.name
    tmp_out = tmp_in.replace('.lua', '.obf.lua')
    cmd = ['python', 'obf.py', tmp_in, tmp_out]
    if seed is not None: cmd += ['--seed', str(seed)]
    subprocess.run(cmd, check=True)
    with open(tmp_out) as f: result = f.read()
    os.remove(tmp_in); os.remove(tmp_out)
    return result
```
