# YARA Rule Compatibility — technical detail

*Applies to scanner **3.4.0**. History of changes: [release notes](../../../CHANGELOG.md).*

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

## 4. Which YARA library each agent ships

The agent version does **not** tell you which YARA library you get. The **platform** does.

Measured directly on four endpoints by running an introspection snippet through Action
Center, so these are the runtimes as reported by the agents themselves:

| Agent version | OS | Embedded Python | yara-python / libyara |
|---|---|---|---|
| 9.1.0.20483 | Windows Server 2019 | 3.12.4 | **4.1.0** |
| 9.2.0.90 | Windows Server 2022 | 3.12.4 | **4.1.0** |
| 9.3.0.209 | Windows Server 2022 | 3.12.4 | **4.1.0** |
| 9.2.0.134 | Ubuntu 22.04 | 3.13.1 | **3.11.0** |

Three Windows agents spanning **9.1 → 9.2 → 9.3** report the byte-identical Python build
string and the same libyara 4.1.0. **"Newer agent means newer YARA" is false** across that
range.

Two things follow that are easy to get backwards:

- **Do not plan a rule pack around an agent-version upgrade.** Upgrading 9.1 → 9.3 on
  Windows changed neither the Python nor the libyara version. If a rule is rejected today,
  the same rule is rejected after the upgrade.
- **Python version and YARA version are independent.** Linux ships a *newer* Python (3.13.1)
  with a much *older* libyara (3.11.0) than Windows. Never infer one from the other.

> **Scope of these measurements.** Three Windows samples, one Linux sample, all on one
> tenant. **macOS was never probed** and is a third runtime variant with unknown versions.
> Treat the table as strong evidence that version-based reasoning fails, not as a
> guaranteed matrix for every build in your estate. §8 shows how to check your own.

## 5. Windows and Linux agents differ

Because the two platforms carry different libyara versions, the **same rule pack can behave
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

## 6. What the scanner does with incompatible rules

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

## 7. Practical guidance

- **Restrict packs intended for XDR agents** to `pe`, `elf`, `math`, `hash` and `time`.
- **Test a new pack on a small folder first** and read `skipped_rules_count` and `top_rules`
  in the summary before running it fleet-wide.
- **Prefer fewer, more specific rules** over large community packs. Compile time is rarely
  the constraint; match volume is — a single noisy rule can generate tens of thousands of
  matches.
- **Do not use "it works with my local Python" as evidence** of agent compatibility. Compare
  `yara.YARA_VERSION` instead.

## 8. Checking what an endpoint actually supports

The authoritative answer comes from the endpoint itself. Run this as an Action Center
snippet to enumerate the modules its libyara accepts:

```python
import platform, sys, yara
print("host     ", platform.node(), "|", platform.platform())
print("python   ", sys.version.split()[0], "| frozen:", getattr(sys, "frozen", False))
print("libyara  ", yara.YARA_VERSION, "| yara-python", yara.__version__)
for m in ("pe","elf","math","hash","cuckoo","magic","dotnet","time",
          "console","string","macho","dex","lnk"):
    try:
        yara.compile(source='import "%s"\nrule t { condition: true }' % m)
        print("  %-8s OK" % m)
    except Exception as e:
        print("  %-8s FAIL  %s" % (m, e))
```

`frozen: True` confirms you are looking at the agent's embedded interpreter and not a
Python installed on the host.

**Run it once per platform, not once per agent version** — §4 shows the platform is what
changes the answer. One Windows endpoint and one Linux endpoint will normally characterise
your whole estate. Re-check after a major agent release rather than after every minor one,
and check macOS separately if you scan Macs.
