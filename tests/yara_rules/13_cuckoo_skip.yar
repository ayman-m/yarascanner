import "cuckoo"
rule Uses_Cuckoo { condition: cuckoo.network.http_request(/evil\.example/) }
rule Plain_Alongside { strings: $s = "certutil -urlcache" condition: $s }
