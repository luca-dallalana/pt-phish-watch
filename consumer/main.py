import logging
import os

import certstream

import scoring
import storage

logging.basicConfig(
    level=os.environ.get('LOG_LEVEL', 'INFO'),
    format='%(asctime)s %(levelname)s %(message)s',
)
logger = logging.getLogger(__name__)

_DB_PATH = os.environ.get('DB_PATH', '/data/findings.db')
_conn = storage.init_db(_DB_PATH)


def _on_cert(message: dict, context) -> None:
    if message.get('message_type') != 'certificate_update':
        return

    data = message.get('data', {})
    leaf = data.get('leaf_cert', {})

    cert = {
        'fingerprint': leaf.get('fingerprint', ''),
        'issuer': (leaf.get('issuer') or {}).get('O'),
        'not_before': leaf.get('not_before'),
        'not_after': leaf.get('not_after'),
        'seen_at': data.get('seen'),
    }

    for domain in leaf.get('all_domains', []):
        record = scoring.score_domain(domain, cert)
        if record:
            logger.info(
                'flagged %s reason=%s seed=%s',
                record['candidate_domain'],
                record['flag_reason'],
                record['matched_seed'],
            )
            storage.save_cert(_conn, record)


if __name__ == '__main__':
    logger.info('starting consumer db=%s', _DB_PATH)
    certstream.listen_for_events(_on_cert, url='wss://certstream.calidog.io/')
