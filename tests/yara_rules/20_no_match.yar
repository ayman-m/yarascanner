rule NoMatch_A { strings: $a = "this_string_is_not_in_the_corpus_aaaa" condition: $a }
rule NoMatch_B { strings: $b = "this_string_is_not_in_the_corpus_bbbb" condition: $b }
