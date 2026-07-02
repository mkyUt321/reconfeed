from app.matching.engine import compile_keyword_pattern


def test_keyword_matches_case_insensitive():
    pattern = compile_keyword_pattern("Kerberos")
    assert pattern.search("A new kerberos exploit was released")


def test_keyword_respects_word_boundary():
    pattern = compile_keyword_pattern("ad")
    assert not pattern.search("this vulnerability was already known")
    assert pattern.search("AD CS misconfiguration allows privilege escalation")


def test_keyword_matches_multi_word_phrase():
    pattern = compile_keyword_pattern("golden ticket")
    assert pattern.search("Attackers used a Golden Ticket to persist")
    assert not pattern.search("golden hour was not related")


def test_keyword_with_special_regex_characters():
    pattern = compile_keyword_pattern("ntds.dit")
    assert pattern.search("Dumping ntds.dit via vssadmin")
    # the literal dot must not act as a regex wildcard
    assert not pattern.search("ntdsxdit should not match")
