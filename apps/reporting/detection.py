"""Detection-plane capture from the Wazuh Indexer (Layer ③, Phase 2).

Queries OpenSearch for a per-(local day × rule.level) alert rollup and returns
plain dicts for the ``refresh_reporting`` command to upsert into
``mart.agg_detection_daily``. Uses the same connection settings as
``apps.wazuh_ingest.ingest``.

Day bucketing happens in the Indexer via ``time_zone`` so days are local
(Asia/Bangkok) — matching the ticket-plane bucketing.
"""
import logging

from django.conf import settings

import requests

logger = logging.getLogger(__name__)

ALERTS_INDEX = 'wazuh-alerts-*'
LOCAL_TZ = 'Asia/Bangkok'


def _opensearch_url():
    return f'https://{settings.OPENSEARCH_HOST}:{settings.OPENSEARCH_PORT}/{ALERTS_INDEX}/_search'


def _build_query(days, tz):
    return {
        'size': 0,
        'query': {'range': {'@timestamp': {'gte': f'now-{days}d/d'}}},
        'aggs': {
            'per_day': {
                'date_histogram': {
                    'field': '@timestamp',
                    'calendar_interval': 'day',
                    'time_zone': tz,
                    'min_doc_count': 1,
                },
                'aggs': {
                    'per_level': {
                        'terms': {'field': 'rule.level', 'size': 50},
                        'aggs': {'agents': {'cardinality': {'field': 'agent.id'}}},
                    },
                },
            },
        },
    }


def parse_response(payload):
    """Flatten an OpenSearch aggregation response into rows.

    Returns ``[{'day': 'YYYY-MM-DD', 'rule_level': int, 'alert_count': int,
    'agent_count': int}, ...]``. Kept separate from the HTTP call so it is unit
    testable with a fixture.
    """
    rows = []
    day_buckets = (
        payload.get('aggregations', {}).get('per_day', {}).get('buckets', [])
    )
    for day_bucket in day_buckets:
        # key_as_string e.g. '2026-06-15T00:00:00.000+07:00' — the date part is
        # already local because of the time_zone on the histogram.
        day = day_bucket['key_as_string'][:10]
        for level in day_bucket.get('per_level', {}).get('buckets', []):
            rows.append({
                'day': day,
                'rule_level': int(level['key']),
                'alert_count': int(level['doc_count']),
                'agent_count': int(level.get('agents', {}).get('value', 0)),
            })
    return rows


def fetch_detection_daily(days=2, tz=LOCAL_TZ):
    """Fetch the per-(local day × rule.level) rollup for the last ``days`` days.

    Raises on connection/HTTP error — the caller (``refresh_reporting``) guards
    it so a detection-capture failure never aborts the ticket-side refresh.
    """
    response = requests.post(
        _opensearch_url(),
        json=_build_query(days, tz),
        auth=(settings.OPENSEARCH_USER, settings.OPENSEARCH_PASSWORD),
        verify=settings.OPENSEARCH_CA_BUNDLE or settings.OPENSEARCH_VERIFY_SSL,
        timeout=30,
    )
    response.raise_for_status()
    return parse_response(response.json())
