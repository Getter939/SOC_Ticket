"""
Pulls Wazuh alerts (rule.level >= min_level) from OpenSearch and stores them
as WazuhAlert rows.

Rules
─────
• Never raises on connection / HTTP failure — caught, logged, returned in
  the result dict's 'errors' list.
• Per-record parsing errors are caught individually and logged — one bad
  alert must not abort the whole batch.
• A single-row IngestWatermark tracks the last ingested @timestamp so that
  repeat runs only fetch new alerts. The watermark only advances after a
  successful write.
"""

import logging
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from django.utils.dateparse import parse_datetime

import requests

from .models import IngestWatermark, WazuhAlert

logger = logging.getLogger(__name__)

ALERTS_INDEX = 'wazuh-alerts-*'


def _opensearch_url():
    return f'https://{settings.OPENSEARCH_HOST}:{settings.OPENSEARCH_PORT}/{ALERTS_INDEX}/_search'


def _get_watermark():
    watermark, _ = IngestWatermark.objects.get_or_create(pk=1)
    return watermark


def _build_query(min_level, last_timestamp, batch_size):
    # Use >gt< when watermark exists to skip already-ingested alerts; fall back to >=gte>= on first run.
    timestamp_filter = {'gt': last_timestamp.isoformat()} if last_timestamp is not None else {'gte': last_timestamp.isoformat()}

    return {
        'query': {
            'bool': {
                'filter': [
                    {'range': {'rule.level': {'gte': min_level}}},
                    {'range': {'@timestamp': timestamp_filter}},
                ]
            }
        },
        'size': batch_size,
        'sort': [{'@timestamp': 'asc'}],
    }


def _parse_hit(hit):
    """Convert a raw OpenSearch hit into kwargs for WazuhAlert. Raises on bad data."""
    source = hit['_source']
    rule = source.get('rule', {})
    agent = source.get('agent', {})
    mitre = rule.get('mitre', {})
    data = source.get('data', {})
    decoder = source.get('decoder', {})

    timestamp = parse_datetime(source['@timestamp'])
    if timestamp is None:
        raise ValueError(f"Could not parse @timestamp: {source.get('@timestamp')!r}")

    return dict(
        opensearch_id=hit['_id'],
        alert_id=str(source.get('id', '')),
        timestamp=timestamp,
        agent_id=agent.get('id', ''),
        agent_name=agent.get('name', ''),
        agent_ip=agent.get('ip') or None,
        rule_id=str(rule.get('id', '')),
        rule_level=rule.get('level', 0),
        rule_description=rule.get('description', ''),
        rule_groups=rule.get('groups', []) or [],
        mitre_techniques=mitre.get('technique', []) or [],
        mitre_tactics=mitre.get('tactic', []) or [],
        mitre_ids=mitre.get('id', []) or [],
        raw_data=data or {},
        decoder_name=decoder.get('name', ''),
    )


def store_alert_hits(hits, min_level=10, advance_watermark=True):
    """
    Parse and store OpenSearch hit dictionaries.

    Offline fixtures disable watermark updates so demo timestamps cannot
    affect the next production OpenSearch fetch.
    """
    result = {'fetched': len(hits), 'created': 0, 'skipped': 0, 'errors': []}
    new_alerts = []
    newest_timestamp = None

    for hit in hits:
        try:
            source = hit['_source']
            rule_level = int(source.get('rule', {}).get('level', 0))
            if rule_level < min_level:
                result['skipped'] += 1
                continue

            opensearch_id = hit['_id']
            if WazuhAlert.objects.filter(opensearch_id=opensearch_id).exists():
                result['skipped'] += 1
                continue

            kwargs = _parse_hit(hit)
            new_alerts.append(WazuhAlert(**kwargs))
            if newest_timestamp is None or kwargs['timestamp'] > newest_timestamp:
                newest_timestamp = kwargs['timestamp']
        except Exception as exc:
            msg = f"Failed to parse alert {hit.get('_id', '?')}: {exc}"
            logger.error(msg)
            result['errors'].append(msg)

    if new_alerts:
        try:
            created = WazuhAlert.objects.bulk_create(new_alerts, ignore_conflicts=True)
            result['created'] = len(created)
        except Exception as exc:
            msg = f'Bulk create failed: {exc}'
            logger.error(msg)
            result['errors'].append(msg)
            return result

    if advance_watermark and newest_timestamp is not None:
        watermark = _get_watermark()
        if watermark.last_timestamp is None or newest_timestamp > watermark.last_timestamp:
            watermark.last_timestamp = newest_timestamp
            watermark.save(update_fields=['last_timestamp', 'updated_at'])

    return result


def fetch_and_store_alerts(min_level=10, batch_size=500):
    """
    Fetch new Wazuh alerts (rule.level >= min_level) from OpenSearch and
    store them as WazuhAlert rows.

    Returns: {'fetched': N, 'created': N, 'skipped': N, 'errors': [str, ...]}
    """
    result = {'fetched': 0, 'created': 0, 'skipped': 0, 'errors': []}

    watermark = _get_watermark()
    last_timestamp = watermark.last_timestamp
    if last_timestamp is None:
        last_timestamp = timezone.now() - timedelta(hours=24)

    query = _build_query(min_level, last_timestamp, batch_size)

    try:
        response = requests.post(
            _opensearch_url(),
            json=query,
            auth=(settings.OPENSEARCH_USER, settings.OPENSEARCH_PASSWORD),
            verify=settings.OPENSEARCH_CA_BUNDLE or settings.OPENSEARCH_VERIFY_SSL,
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        msg = f'OpenSearch request failed: {exc}'
        logger.error(msg)
        result['errors'].append(msg)
        return result

    hits = payload.get('hits', {}).get('hits', [])
    result['fetched'] = len(hits)

    if not hits:
        return result

    return store_alert_hits(hits, min_level=min_level, advance_watermark=True)
