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

# Known legitimate international/compound brand domains — bypass all pipeline steps
_KNOWN_LEGIT_REGISTERED: frozenset[str] = frozenset([
    'aegonsantander.pt',
    'santanderconsumer.no',
    'santanderconsumer.it',
    'santanderconsumer.co',
])

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
        dist = Levenshtein.distance(candidate_reg, seed)
        max_dist = 1 if len(seed) < 8 else 3
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
            dist = Levenshtein.distance(normalized_reg, seed)
            if 1 <= dist <= 3:
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
        if (len(brand) >= 5 and brand in candidate_part and candidate_part != brand) or \
                (len(brand) <= 4 and brand in part_segments):
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
            if len(brand) < 4:
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
