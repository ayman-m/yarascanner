# YARA Rule Compatibility — technical detail

Companion to the XDR YARA Scanner Guide. Read this if rules that compile on your
workstation are skipped or rejected when the scan runs on an endpoint.

---

## 1. The short answer

The Cortex XDR agent ships **its own embedded Python and its own compiled libyara**. The
YARA modules available to your rules are fixed when that libyara was built — they are a
property of the agent, not of the script, and not of any Python version.

A rule that imports a module the agent's libyara lacks **fails to compile**, and the
scanner **skips it rather than failing the scan**.

## 2. Which modules are available

| | Modules |
|---|---|
| ✅ **Available** | `pe`, `elf`, `math`, `hash`, `time` |
| ❌ **Not available** | `cuckoo`, `magic`, `dotnet`, `console`, `string`, `macho`, `dex`, `lnk` |

Failure looks like this at compile time:

```
yara.SyntaxError: line 1: unknown module "cuckoo"
```

## 3. Why rules work on your workstation but not on the agent

A current `pip install yara-python` gives **libyara 4.5.x**, built with a wider module set.
The agent carries an older build. Same rule file, two different libyara builds, different
result.

To confirm which version your workstation has:

```bash
python -c "import yara; print(yara.__version__, yara.YARA_VERSION)"
```

If that reports 4.5.x while the agent is on 4.1.0, that difference alone explains rules
compiling locally and being skipped on the endpoint.

> **This is not a Python-version issue.** Module availability is a libyara **compile-time**
> property. Python only hosts the library; it cannot add or remove a module that was not
> compiled in. Two agents running different Python versions expose the identical module set.

> ### A documentation trap worth knowing
>
> Cortex documentation suggests that when a script fails you should reproduce it on the same
> endpoint using a *"regular Python 3.7 installation"* and escalate if it works there. That
> guidance **does not hold for compiled extension modules** such as `yara-python`: your local
> install and the agent's embedded one are different builds. A rule working locally proves
> nothing about agent compatibility.
>
> The same documentation still states scripts run **Python 3.7**. The agents actually ship
> considerably newer interpreters. Do not use the documented version to reason about rule
> compatibility.

## 4. Windows and Linux agents differ

The two platforms carry different libyara versions, so the **same rule pack can behave
differently across your fleet**:

| Rule feature | Windows agent | Linux agent |
|---|---|---|
| `base64` / `base64wide` string modifiers | ✅ compiles | ❌ **syntax error** |
| `pe.number_of_imported_functions` | ✅ | ❌ invalid field |
| `xor` ranges, `nocase`, `wide`, regex modifiers | ✅ | ✅ |
| `math.entropy`, `math.mean` | ✅ | ✅ |
| `hash.sha256`, `time.now` | ✅ | ✅ |
| `pe.is_signed`, `console.log`, `string.to_int`, `defined` keyword | ❌ | ❌ |

**For a single pack deployed across both platforms**, stay within the older feature set, or
maintain separate packs per platform. A pack using `base64` modifiers will fail to compile
on Linux agents.

## 5. What the scanner does with incompatible rules

Rules that need an unavailable module are **skipped, not fatal**. The scan proceeds with
everything else.

Detection is gated on an actual `import "<module>"` statement in the rule source, so a rule
that merely contains the literal string `"cuckoo.conf"` is **not** wrongly dropped.

Skipped rules are visible in three places:

- `skipped_rules_count` in `scan_summary_<run_id>.json`
- `yara_processing_<run_id>.log` on the endpoint
- each one written out as `skipped_rule_<name>_<module>.yar` for inspection

> **If a rule pack appears to shrink silently, `skipped_rules_count` is where to look.** It
> tells you exactly how many rules were dropped and which module caused each.

## 6. Practical guidance

- **Restrict packs intended for XDR agents** to `pe`, `elf`, `math`, `hash` and `time`.
- **Test a new pack on a small folder first** and read `skipped_rules_count` and `top_rules`
  in the summary before running it fleet-wide.
- **Prefer fewer, more specific rules** over large community packs. Compile time is rarely
  the constraint; match volume is — a single noisy rule can generate tens of thousands of
  matches.
- **Do not use "it works with my local Python" as evidence** of agent compatibility. Compare
  `yara.YARA_VERSION` instead.

## 7. Checking what an endpoint actually supports

The authoritative answer comes from the endpoint itself. Run this as an Action Center
snippet to enumerate the modules its libyara accepts:

```python
import yara
print("yara-python", yara.__version__, "| libyara", yara.YARA_VERSION)
for m in ("pe","elf","math","hash","cuckoo","magic","dotnet","time",
          "console","string","macho","dex","lnk"):
    try:
        yara.compile(source='import "%s"\nrule t { condition: true }' % m)
        print("  %-8s OK" % m)
    except Exception as e:
        print("  %-8s FAIL  %s" % (m, e))
```

This is worth running once per agent version in your estate, since the answer is a property
of the agent build rather than of anything you control.
