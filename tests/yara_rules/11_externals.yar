rule Ext_TxtFile { condition: filename matches /\.txt$/i }
rule Ext_InTemp  { condition: filepath contains "yara_corpus" }
