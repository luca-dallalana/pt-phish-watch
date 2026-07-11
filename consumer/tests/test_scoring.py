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
    # сgd1.pt: Cyrillic с makes raw distance 2 from cgd.pt (> max_dist=1 for 6-char seed),
    # but after normalization cgd1.pt is distance 1 (≤ max_dist=1)
    result = scoring.score_domain('сgd1.pt', _cert('FP-HOMO-01'))
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


def test_known_legit_registered():
    # Santander subsidiaries and other legitimate compound domains must not be flagged
    for domain, fp in [
        ('santanderconsumer.es', 'FP-KL-01'),
        ('santanderconsumer.cl', 'FP-KL-02'),
        ('santandersecuritiesservices.com', 'FP-KL-03'),
        ('santanderglobalcards.com', 'FP-KL-04'),
        ('novobancocultura.pt', 'FP-KL-05'),
        ('vodafoneparedesdecoura.pt', 'FP-KL-06'),
        ('stare-na-nowo.pl', 'FP-KL-07'),
    ]:
        assert scoring.score_domain(domain, _cert(fp)) is None, f"should not flag {domain}"


def test_known_legit_registered_new():
    for domain, fp in [
        ('dge.mec.pt', 'FP-MEC-01'),           # Portuguese MoE subdomain
        ('www.mec.pt', 'FP-MEC-02'),
        ('mway.io', 'FP-MWAY-01'),             # DevOps platform
        ('dev.k8s.mway.io', 'FP-MWAY-02'),
        ('vodafone-ip.de', 'FP-VFIP-01'),      # German Vodafone infra
        ('forecast.vodafone-topangebote.net', 'FP-VFTOP-01'),
        ('ems.vodafone-topangebote.net', 'FP-VFTOP-02'),
    ]:
        assert scoring.score_domain(domain, _cert(fp)) is None, f"should not flag {domain}"


def test_meo_dre_segment_excluded():
    assert scoring.score_domain('umami.meo-mai-moi.com', _cert('FP-MEO-01')) is None
    assert scoring.score_domain('account.meo-lab.ch', _cert('FP-MEO-02')) is None
    assert scoring.score_domain('hibachi.dre-tech.co', _cert('FP-DRE-01')) is None
    assert scoring.score_domain('dre-allen.com', _cert('FP-DRE-02')) is None


def test_spf_sec_not_flagged():
    assert scoring.score_domain('spf.pt', _cert('FP-SPF-01')) is None
    assert scoring.score_domain('www.sec.pt', _cert('FP-SEC-01')) is None


def test_santander_city_not_flagged():
    # City of Santander .es domains with no banking keywords must not be flagged
    for domain, fp in [
        ('santandermunicipio.es', 'FP-CITY-01'),
        ('turismosantander.es', 'FP-CITY-02'),
        ('santandercantabria.de', 'FP-CITY-03'),
    ]:
        assert scoring.score_domain(domain, _cert(fp)) is None, f"should not flag city domain {domain}"


def test_santander_phishing_flagged():
    # Santander phishing with non-ccTLD or with banking keyword must still be flagged
    for domain, fp in [
        ('santander-cliente.info', 'FP-SANT-01'),          # non-ccTLD
        ('verificacion-bancosantander.es', 'FP-SANT-02'),  # ccTLD but has 'banco' keyword
        ('login-santander.pt', 'FP-SANT-03'),              # .pt always flagged
    ]:
        result = scoring.score_domain(domain, _cert(fp))
        assert result is not None, f"should flag phishing domain {domain}"
        assert result['matched_seed'] == 'santander.pt'


def test_nos_segment_excluded():
    # 'nos' is a global abbreviation — hyphen-delimited segment matches must not fire
    assert scoring.score_domain('nos-assurance.fr', _cert('FP-NOS-01')) is None
    assert scoring.score_domain('nos-company.jp', _cert('FP-NOS-02')) is None


def test_sns_segment_excluded():
    # 'sns' is a global abbreviation — hyphen-delimited segment matches must not fire
    assert scoring.score_domain('sns-insights.io', _cert('FP-SNS-01')) is None
    assert scoring.score_domain('sns-marketing.com', _cert('FP-SNS-02')) is None


def test_nos_subdomain_abuse_still_detected():
    # subdomain abuse on nos.pt must still be caught even with segment exclusion
    result = scoring.score_domain('nos.pt.malicious.com', _cert('FP-NOSSUB-01'))
    assert result is not None
    assert result['flag_reason'] == 'subdomain'
    assert result['matched_seed'] == 'nos.pt'


def test_dedup_same_fingerprint():
    fp = 'FP-DEDUP-UNIQUE-01'
    # First call with a flagged domain — should succeed
    first = scoring.score_domain('cgd1.pt', _cert(fp))
    assert first is not None
    # Second call with a different domain but same cert fingerprint — deduped
    second = scoring.score_domain('cgd2.pt', _cert(fp))
    assert second is None
