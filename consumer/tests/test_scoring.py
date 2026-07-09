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
    # login(20) + seguro(20) + conta(15) = 55 > 40, no seed brand name in domain
    result = scoring.score_domain('login-seguro-conta.com', _cert('FP-KW-01'))
    assert result is not None
    assert result['flag_reason'] == 'keyword'
    assert result['score'] == 55


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


def test_brand_contains_novobanco():
    for domain, fp in [
        ('loguin-novobanco.com', 'FP-BC-01'),
        ('novobanco-loguin.com', 'FP-BC-02'),
        ('app-novobanco.com', 'FP-BC-03'),
        ('novobanco-app.com', 'FP-BC-04'),
        ('novobanconet.com', 'FP-BC-05'),
    ]:
        result = scoring.score_domain(domain, _cert(fp))
        assert result is not None, f"missed {domain}"
        assert result['flag_reason'] == 'brand_contains'
        assert result['matched_seed'] == 'novobanco.pt'


def test_brand_contains_montepio():
    for domain, fp in [
        ('montepio-app.com', 'FP-BC-06'),
        ('montepio-loguin.com', 'FP-BC-07'),
        ('loguin-montepio.com', 'FP-BC-08'),
    ]:
        result = scoring.score_domain(domain, _cert(fp))
        assert result is not None, f"missed {domain}"
        assert result['flag_reason'] == 'brand_contains'
        assert result['matched_seed'] == 'montepio.pt'


def test_segment_levenshtein_nbway():
    # nbway is distance 1 from mbway (n→m)
    result = scoring.score_domain('nbway-app.com', _cert('FP-SEG-01'))
    assert result is not None
    assert result['flag_reason'] == 'levenshtein'
    assert result['matched_seed'] == 'mbway.pt'
    assert result['edit_distance'] == 1


def test_segment_levenshtein_sanrtander():
    # sanrtander is distance 1 from santander (extra r)
    result = scoring.score_domain('sanrtander.com', _cert('FP-SEG-02'))
    assert result is not None
    assert result['flag_reason'] == 'levenshtein'
    assert result['matched_seed'] == 'santander.pt'
    assert result['edit_distance'] == 1


def test_dedup_same_fingerprint():
    fp = 'FP-DEDUP-UNIQUE-01'
    # First call with a flagged domain — should succeed
    first = scoring.score_domain('cgd1.pt', _cert(fp))
    assert first is not None
    # Second call with a different domain but same cert fingerprint — deduped
    second = scoring.score_domain('cgd2.pt', _cert(fp))
    assert second is None
