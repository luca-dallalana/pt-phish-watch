import base64
import hashlib
import json
import logging
import os
import struct
import time
from pathlib import Path

import requests
from asn1crypto import x509 as asn1_x509

import scoring
import storage

logging.basicConfig(
    level=os.environ.get('LOG_LEVEL', 'INFO'),
    format='%(asctime)s %(levelname)s %(message)s',
)
logger = logging.getLogger(__name__)

_DB_PATH = os.environ.get('DB_PATH', '/data/findings.db')
_STATE_PATH = os.environ.get('STATE_PATH', '/data/ct_state.json')
_POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', '10'))
_BATCH_SIZE = 256
_HEADERS = {'User-Agent': 'pt-phish-watch/1.0'}

CT_LOGS: list[str] = [
    'https://ct.googleapis.com/logs/us1/argon2026h2/',
    'https://ct.googleapis.com/logs/us1/argon2026h1/',
    'https://ct.cloudflare.com/logs/nimbus2026/',
]


def _load_state() -> dict:
    try:
        return json.loads(Path(_STATE_PATH).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_state(state: dict) -> None:
    Path(_STATE_PATH).write_text(json.dumps(state))


def _get_tree_size(log_url: str) -> int | None:
    try:
        resp = requests.get(f'{log_url}ct/v1/get-sth', headers=_HEADERS, timeout=10)
        resp.raise_for_status()
        return resp.json()['tree_size']
    except Exception as exc:
        logger.warning('get-sth failed %s: %s', log_url, exc)
        return None


def _get_entries(log_url: str, start: int, end: int) -> list[dict]:
    try:
        resp = requests.get(
            f'{log_url}ct/v1/get-entries',
            params={'start': start, 'end': end},
            headers=_HEADERS,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get('entries', [])
    except Exception as exc:
        logger.warning('get-entries failed %s [%d-%d]: %s', log_url, start, end, exc)
        return []


def _extract_domains(tbs) -> list[str]:
    domains = set()
    try:
        exts = tbs['extensions']
        if exts:
            for ext in exts:
                if ext['extn_id'].native == 'subject_alt_name':
                    for gn in ext['extn_value'].parsed:
                        if gn.name == 'dns_name':
                            val = gn.chosen.native
                            if val:
                                domains.add(val.lower())
    except Exception:
        pass
    return list(domains)


def _extract_issuer(tbs) -> str | None:
    try:
        for rdn in tbs['issuer'].chosen:
            for atv in rdn:
                if atv['type'].native == 'organization_name':
                    return atv['value'].native
    except Exception:
        pass
    return None


def _extract_validity(tbs) -> tuple[int | None, int | None]:
    try:
        not_before = int(tbs['validity']['not_before'].native.timestamp())
        not_after = int(tbs['validity']['not_after'].native.timestamp())
        return not_before, not_after
    except Exception:
        return None, None


def _parse_entry(entry: dict) -> tuple[list[str], dict]:
    try:
        leaf = base64.b64decode(entry['leaf_input'])
        ct_ts_ms = struct.unpack_from('>Q', leaf, 2)[0]
        entry_type = struct.unpack_from('>H', leaf, 10)[0]
        pos = 12

        if entry_type == 0:  # x509_entry
            cert_len = struct.unpack_from('>I', b'\x00' + leaf[pos:pos + 3])[0]
            pos += 3
            raw = leaf[pos:pos + cert_len]
            tbs = asn1_x509.Certificate.load(raw)['tbs_certificate']
            fingerprint = hashlib.sha256(raw).hexdigest().upper()
        elif entry_type == 1:  # precert_entry
            pos += 32  # issuer_key_hash
            tbs_len = struct.unpack_from('>I', b'\x00' + leaf[pos:pos + 3])[0]
            pos += 3
            raw = leaf[pos:pos + tbs_len]
            tbs = asn1_x509.TbsCertificate.load(raw)
            fingerprint = hashlib.sha256(raw).hexdigest().upper()
        else:
            return [], {}

        not_before, not_after = _extract_validity(tbs)
        return _extract_domains(tbs), {
            'fingerprint': fingerprint,
            'issuer': _extract_issuer(tbs),
            'not_before': not_before,
            'not_after': not_after,
            'seen_at': ct_ts_ms / 1000.0,
        }
    except Exception as exc:
        logger.debug('failed to parse entry: %s', exc)
        return [], {}


def _process_log(log_url: str, state: dict, conn) -> None:
    tree_size = _get_tree_size(log_url)
    if tree_size is None:
        return

    log_name = log_url.rstrip('/').split('/')[-1]

    if log_url not in state:
        state[log_url] = max(0, tree_size - 5000)

    last = state[log_url]
    if last >= tree_size:
        logger.debug('%s: up to date at index %d', log_name, last)
        return

    logger.info('%s: %d new entries', log_name, tree_size - last)

    pos = last
    while pos < tree_size:
        end = min(pos + _BATCH_SIZE - 1, tree_size - 1)
        entries = _get_entries(log_url, pos, end)
        if not entries:
            break

        for entry in entries:
            domains, cert = _parse_entry(entry)
            for domain in domains:
                record = scoring.score_domain(domain, cert)
                if record:
                    logger.info(
                        'flagged %s reason=%s seed=%s',
                        record['candidate_domain'],
                        record['flag_reason'],
                        record['matched_seed'],
                    )
                    storage.save_cert(conn, record)

        pos = end + 1
        state[log_url] = pos
        _save_state(state)


if __name__ == '__main__':
    conn = storage.init_db(_DB_PATH)
    state = _load_state()
    logger.info('starting consumer db=%s logs=%d', _DB_PATH, len(CT_LOGS))

    while True:
        logger.debug('poll cycle start')
        for log_url in CT_LOGS:
            _process_log(log_url, state, conn)
        time.sleep(_POLL_INTERVAL)
