import scoring


def _cert(fingerprint: str) -> dict:
    return {
        'fingerprint': fingerprint,
        'issuer': "Let's Encrypt",
        'not_before': 1700000000,
        'not_after': 1731536000,
        'seen_at': 1700000000.0,
    }


def test_prefilter_legitimate_seed():
    assert scoring.score_domain('cgd.pt', _cert('FP-PREFILTER-01')) is None


def test_levenshtein_hit():
    # cgd1.pt has registered domain cgd1.pt — Levenshtein distance 1 from cgd.pt
    result = scoring.score_domain('cgd1.pt', _cert('FP-LEV-01'))
    assert result is not None
    assert result['flag_reason'] == 'levenshtein'
    assert result['matched_seed'] == 'cgd.pt'
    assert result['edit_distance'] == 1


def test_homoglyph_hit():
    # сgd-pt.pt: Cyrillic с makes raw distance 4 from cgd.pt (> 3),
    # but after normalization cgd-pt.pt is distance 3 (≤ 3)
    result = scoring.score_domain('сgd-pt.pt', _cert('FP-HOMO-01'))
    assert result is not None
    assert result['flag_reason'] == 'homoglyph'
    assert result['matched_seed'] == 'cgd.pt'


def test_keyword_hit():
    # mbway(25) + login(20) = 45 > 40
    result = scoring.score_domain('mbway-login.com', _cert('FP-KW-01'))
    assert result is not None
    assert result['flag_reason'] == 'keyword'
    assert result['score'] == 45


def test_keyword_below_threshold():
    # login(20) + banco(10) = 30 ≤ 40
    assert scoring.score_domain('login-banco.com', _cert('FP-KW-02')) is None


def test_subdomain_abuse():
    # cgd.pt appears as labels inside the candidate before the registered domain
    result = scoring.score_domain('cgd.pt.malicious.com', _cert('FP-SUB-01'))
    assert result is not None
    assert result['flag_reason'] == 'subdomain'
    assert result['matched_seed'] == 'cgd.pt'


def test_unrelated_domain():
    assert scoring.score_domain('google.com', _cert('FP-UNREL-01')) is None


def test_dedup_same_fingerprint():
    fp = 'FP-DEDUP-UNIQUE-01'
    # First call with a flagged domain — should succeed
    first = scoring.score_domain('cgd1.pt', _cert(fp))
    assert first is not None
    # Second call with a different domain but same cert fingerprint — deduped
    second = scoring.score_domain('cgd2.pt', _cert(fp))
    assert second is None
