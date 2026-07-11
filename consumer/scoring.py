import unicodedata
from collections import deque

import Levenshtein
import tldextract

HOMOGLYPH_MAP: dict[str, str] = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
    'ο': 'o', 'ρ': 'r',
    'ℓ': 'l', 'ℬ': 'b',
}

KEYWORD_SCORES: dict[str, int] = {
    'seguro': 20,
    'login': 20,
    'conta': 15,
    'acesso': 15,
    'verify': 15,
    'secure': 15,
    'portal': 10,
    'banco': 10,
    'financas': 10,
    'pagamento': 10,
    'mbway': 25,
    'multibanco': 25,
}

SEED_DOMAINS: list[str] = [
    'cgd.pt', 'millenniumbcp.pt', 'novobanco.pt', 'santander.pt',
    'montepio.pt', 'bancobpi.pt', 'abancaportugal.pt', 'activobank.pt',
    'portaldasfinancas.gov.pt', 'eportugal.gov.pt', 'sns.gov.pt',
    'dre.pt', 'irn.mj.pt', 'sef.pt', 'at.gov.pt',
    'mbway.pt', 'multibanco.pt', 'ifthenpay.com', 'eupago.pt',
    'meo.pt', 'nos.pt', 'vodafone.pt', 'nowo.pt',
]


def _get_registered(domain: str) -> str:
    ext = tldextract.extract(domain)
    if not ext.domain or not ext.suffix:
        return ''
    return f"{ext.domain}.{ext.suffix}"


SEED_REGISTERED: frozenset[str] = frozenset(_get_registered(d) for d in SEED_DOMAINS)

# Seeds excluded from registered-domain Levenshtein — structural noise exceeds signal
# (still active via brand_contains, segment Levenshtein, keyword, and subdomain steps)
_LEVENSHTEIN_EXCLUDED_SEEDS: frozenset[str] = frozenset([
    'at.gov.pt',   # 'at' matches any X.gov.Y domain; brand too short for brand_contains
    'sns.gov.pt',  # 'sns' is a global abbreviation (Japan, Scotland, etc.)
])

# Known legitimate international/compound brand domains — bypass all pipeline steps
_KNOWN_LEGIT_REGISTERED: frozenset[str] = frozenset([
    # Santander subsidiaries
    'aegonsantander.pt',
    'santanderconsumer.no',
    'santanderconsumer.it',
    'santanderconsumer.co',
    'santanderconsumer.cl',
    'santanderconsumer.ca',
    'santanderconsumer.es',
    'santanderconsumer.se',
    'santanderconsumer.fr',
    'santanderconsumer.dk',
    'santanderconsumer.com',
    'santandersecuritiesservices.com',
    'santandersecuritiesservices.es',
    'santanderglobalcards.com',
    'santanderauto.systems',
    'santanderassetmanagement.es',
    'santanderinternationalbankingconference.com',
    'santanderaccionistaseinversores.com',
    # Vodafone event/service domains
    'vodafoneparedesdecoura.pt',
    'vodafoneparedesdecoura.com',
    'vodafonexdsl.co.uk',
    # Novo Banco cultural foundation
    'novobancocultura.pt',
    # Polish telecom (nowo brand unrelated to nowo.pt)
    'stare-na-nowo.pl',
    # Legitimate Portuguese entities (1 edit from sef.pt)
    'spf.pt',
    'sec.pt',
    # Portuguese Ministry of Education (mec.pt is 1 edit from meo.pt)
    'mec.pt',
    # Legitimate DevOps/payment platform (mway segment is 1 edit from mbway)
    'mway.io',
    # German Vodafone infrastructure (brand_contains on vodafone)
    'vodafone-ip.de',
    'vodafone-topangebote.net',
])

# Brands excluded from segment Levenshtein because their 1-edit neighbours are common words
_SEGMENT_LEV_EXCLUDED_BRANDS: frozenset[str] = frozenset(['eportugal'])

# Brands that require a word-boundary match in brand_contains (position 0 or after '-')
# Used for brands whose name is a suffix of common legitimate words (e.g. "portugal" ⊂ "eportugal")
_BOUNDARY_ONLY_BRANDS: frozenset[str] = frozenset(['eportugal'])

# Short brands (3-4 chars) excluded from segment brand_contains — global abbreviations/words
# that produce too many false positives when matched as exact hyphen-delimited segments.
# Seeds remain active via Levenshtein, keyword, and subdomain steps.
_BRAND_SEGMENT_EXCLUDED: frozenset[str] = frozenset([
    'nos',  # French "our", common non-PT abbreviation
    'sns',  # global tech/social abbreviation (Japan, Scotland, AWS, etc.)
    'meo',  # Italian/generic word ("cat"), common syllable globally
    'dre',  # common abbreviation/name globally (Dr., André, etc.)
])

# Brands that share their name with a city/region — brand_contains for these requires
# either a non-ccTLD suffix or a banking keyword, except when suffix == 'pt'.
_BRAND_CITY_DISAMBIGUATION: frozenset[str] = frozenset(['santander'])

# Maps each seed's domain part (no TLD) to its full registered seed, for brand-level checks
_SEED_BRAND_MAP: dict[str, str] = {
    tldextract.extract(s).domain: _get_registered(s)
    for s in SEED_DOMAINS
    if tldextract.extract(s).domain
}

SEEN_FINGERPRINTS: set[str] = set()
_FINGERPRINT_QUEUE: deque[str] = deque()

_DEDUP_MAX = 10_000
_DEDUP_EVICT = 1_000


def _normalize(domain: str) -> str:
    decomposed = unicodedata.normalize('NFKD', domain)
    stripped = ''.join(c for c in decomposed if not unicodedata.combining(c))
    return ''.join(HOMOGLYPH_MAP.get(c, c) for c in stripped)


def _add_fingerprint(fingerprint: str) -> None:
    if len(SEEN_FINGERPRINTS) >= _DEDUP_MAX:
        evicted = [_FINGERPRINT_QUEUE.popleft() for _ in range(min(_DEDUP_EVICT, len(_FINGERPRINT_QUEUE)))]
        SEEN_FINGERPRINTS.difference_update(evicted)
    SEEN_FINGERPRINTS.add(fingerprint)
    _FINGERPRINT_QUEUE.append(fingerprint)


def score_domain(domain: str, cert: dict) -> dict | None:
    fingerprint = cert.get('fingerprint', '')
    if fingerprint and fingerprint in SEEN_FINGERPRINTS:
        return None

    if domain.startswith('*.'):
        domain = domain[2:]

    domain = domain.lower()
    candidate_reg = _get_registered(domain)
    if not candidate_reg or candidate_reg in SEED_REGISTERED or candidate_reg in _KNOWN_LEGIT_REGISTERED:
        return None

    cand_domain_part = tldextract.extract(candidate_reg).domain
    for seed in SEED_REGISTERED:
        if seed in _LEVENSHTEIN_EXCLUDED_SEEDS:
            continue
        dist = Levenshtein.distance(candidate_reg, seed)
        max_dist = 1 if len(seed) < 10 else 3
        if 1 <= dist <= max_dist:
            if cand_domain_part == tldextract.extract(seed).domain:
                continue
            if fingerprint:
                _add_fingerprint(fingerprint)
            return {
                'candidate_domain': domain,
                'matched_seed': seed,
                'flag_reason': 'levenshtein',
                'score': 0,
                'edit_distance': dist,
                'issuer': cert.get('issuer'),
                'not_before': cert.get('not_before'),
                'not_after': cert.get('not_after'),
                'seen_at': cert.get('seen_at'),
                'fingerprint': fingerprint,
            }

    normalized_reg = _normalize(candidate_reg)
    if normalized_reg != candidate_reg:
        for seed in SEED_REGISTERED:
            if seed in _LEVENSHTEIN_EXCLUDED_SEEDS:
                continue
            dist = Levenshtein.distance(normalized_reg, seed)
            max_dist = 1 if len(seed) < 10 else 3
            if 1 <= dist <= max_dist:
                if fingerprint:
                    _add_fingerprint(fingerprint)
                return {
                    'candidate_domain': domain,
                    'matched_seed': seed,
                    'flag_reason': 'homoglyph',
                    'score': 0,
                    'edit_distance': dist,
                    'issuer': cert.get('issuer'),
                    'not_before': cert.get('not_before'),
                    'not_after': cert.get('not_after'),
                    'seen_at': cert.get('seen_at'),
                    'fingerprint': fingerprint,
                }

    candidate_part = tldextract.extract(domain).domain
    part_segments = set(candidate_part.split('-'))

    for brand, seed in _SEED_BRAND_MAP.items():
        if len(brand) >= 5:
            idx = candidate_part.find(brand)
            if idx == -1 or candidate_part == brand:
                continue
            if brand in _BOUNDARY_ONLY_BRANDS and not (idx == 0 or candidate_part[idx - 1] == '-'):
                continue
        elif 3 <= len(brand) <= 4:
            if brand in _BRAND_SEGMENT_EXCLUDED or brand not in part_segments:
                continue
        else:
            continue
        if brand in _BRAND_CITY_DISAMBIGUATION:
            tld_suffix = tldextract.extract(domain).suffix
            has_keyword = any(kw in domain for kw in KEYWORD_SCORES)
            if len(tld_suffix) == 2 and tld_suffix != 'pt' and not has_keyword:
                continue
        if fingerprint:
            _add_fingerprint(fingerprint)
        return {
            'candidate_domain': domain,
            'matched_seed': seed,
            'flag_reason': 'brand_contains',
            'score': 0,
            'edit_distance': None,
            'issuer': cert.get('issuer'),
            'not_before': cert.get('not_before'),
            'not_after': cert.get('not_after'),
            'seen_at': cert.get('seen_at'),
            'fingerprint': fingerprint,
        }

    for segment in part_segments | {candidate_part}:
        if len(segment) < 4:
            continue
        for brand, seed in _SEED_BRAND_MAP.items():
            if len(brand) < 5 or brand in _SEGMENT_LEV_EXCLUDED_BRANDS:
                continue
            if Levenshtein.distance(segment, brand) == 1:
                if fingerprint:
                    _add_fingerprint(fingerprint)
                return {
                    'candidate_domain': domain,
                    'matched_seed': seed,
                    'flag_reason': 'levenshtein',
                    'score': 0,
                    'edit_distance': 1,
                    'issuer': cert.get('issuer'),
                    'not_before': cert.get('not_before'),
                    'not_after': cert.get('not_after'),
                    'seen_at': cert.get('seen_at'),
                    'fingerprint': fingerprint,
                }

    keyword_score = sum(pts for kw, pts in KEYWORD_SCORES.items() if kw in domain)
    if keyword_score > 40:
        matched_seed = min(SEED_REGISTERED, key=lambda s: Levenshtein.distance(candidate_reg, s))
        if fingerprint:
            _add_fingerprint(fingerprint)
        return {
            'candidate_domain': domain,
            'matched_seed': matched_seed,
            'flag_reason': 'keyword',
            'score': keyword_score,
            'edit_distance': None,
            'issuer': cert.get('issuer'),
            'not_before': cert.get('not_before'),
            'not_after': cert.get('not_after'),
            'seen_at': cert.get('seen_at'),
            'fingerprint': fingerprint,
        }

    labels = domain.split('.')
    for seed in SEED_REGISTERED:
        seed_labels = seed.split('.')
        seed_len = len(seed_labels)
        for i in range(len(labels) - seed_len):
            if labels[i:i + seed_len] == seed_labels:
                if fingerprint:
                    _add_fingerprint(fingerprint)
                return {
                    'candidate_domain': domain,
                    'matched_seed': seed,
                    'flag_reason': 'subdomain',
                    'score': 0,
                    'edit_distance': None,
                    'issuer': cert.get('issuer'),
                    'not_before': cert.get('not_before'),
                    'not_after': cert.get('not_after'),
                    'seen_at': cert.get('seen_at'),
                    'fingerprint': fingerprint,
                }

    return None
