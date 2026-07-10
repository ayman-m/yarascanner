import "hash"
rule High_Entropy_Region {
    condition:
        filesize > 64 and math.entropy(0, filesize) >= 7.2
}
rule Known_Hash_Placeholder {
    condition:
        filesize < 1048576 and hash.md5(0, filesize) == "00000000000000000000000000000000"
}
