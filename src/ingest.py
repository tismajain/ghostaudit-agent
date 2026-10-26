"""Participant inputs and record-sized structured evidence. PDF/PNG are unsupported."""
import csv
import json
import re
import sqlite3
from pathlib import Path

from src.schemas import timestamp

# Schema semantics, not case identifiers. Unknown collections remain unknown.
COLLECTIONS = {
    'customer_profiles': ('account_service', 'USER_PROFILE'),
    'customer_search_documents': ('search_service', 'SEARCH_INDEX_ENTRY'),
    'search_documents': ('search_service', 'SEARCH_INDEX_ENTRY'),
    'customer_analytics_profiles': ('analytics_platform', 'ANALYTICS_PROFILE'),
    'customer_analytics_reports': ('analytics_platform', 'PRODUCT_TELEMETRY'),
    'support_records': ('support_platform', 'SUPPORT_MESSAGE'),
    'support_messages': ('support_platform', 'SUPPORT_MESSAGE'),
    'support_attachments': ('support_platform', 'SUPPORT_ATTACHMENT'),
    'customer_exports': ('export_service', 'USER_EXPORT'),
    'customer_export_jobs': ('export_service', 'USER_EXPORT'),
    'connector_subscriptions': ('integration_service', 'DATA_FLOW'),
    'backup_restore_entries': ('backup_service', 'BACKUP_ARCHIVE'),
    'security_audit_records': ('security_service', 'SECURITY_AUDIT_LOG'),
    'security_audit_events': ('security_service', 'SECURITY_AUDIT_LOG'),
    'deleted_customer_references': ('identity_service', 'ACCOUNT_TOMBSTONE'),
    'secondary_identifiers': ('identity_service', 'SECONDARY_IDENTIFIER'),
}
SERVICE_COLLECTIONS = {
    ('account_service', 'profile_lookups'): 'USER_PROFILE',
    ('search_service', 'index_queries'): 'SEARCH_INDEX_ENTRY',
    ('analytics_platform', 'profiles'): 'ANALYTICS_PROFILE',
    ('support_platform', 'tickets'): 'SUPPORT_MESSAGE',
    ('security_service', 'audit_records'): 'SECURITY_AUDIT_LOG',
    ('backup_service', 'restore_entries'): 'BACKUP_ARCHIVE',
    ('integration_service', 'connectors'): 'DATA_FLOW',
    ('export_service', 'exports'): 'USER_EXPORT',
}
DATE = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z')
RESOURCE = re.compile(r'\b[a-z][a-z0-9_]*_\d+\b', re.I)


def read_csv(path):
    with path.open(encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


def read_ids(path):
    values = path.read_text().splitlines()
    assert values and len(values) == len(set(values)) and all(re.fullmatch(r'case_\d+', s) for s in values)
    return set(values)


def decode_value(value):
    # Some log routers escape each nested quoted scalar one or more times.
    # Decode only balanced transport quote wrappers, never trim arbitrary IDs.
    for _ in range(4):
        wrapped = re.fullmatch(r'\\+"(.*?)\\+"', value, re.S)
        if not wrapped:
            break
        value = wrapped[1]
    if value.lower() in ('true', 'false', 'null'):
        return {'true': True, 'false': False, 'null': None}[value.lower()]
    return value


def collection_semantics(collection):
    if collection in COLLECTIONS:
        return COLLECTIONS[collection]
    # Explicit replica table suffixes describe the same record category in another store.
    for base, value in COLLECTIONS.items():
        if collection.startswith(base + '_'):
            return value
    return '', ''


def load(root):
    dataset = root / 'dataset'
    csvs = {name: read_csv(dataset / (name + '.csv')) for name in (
        'sample_deletion_requests', 'user_identities', 'user_audit_log', 'system_activity',
        'deletion_rules', 'evidence_files')}
    units, scopes, unsupported, errors = [], [], [], []

    def add(file, data, system='', category='', observed='', context='', text='', location='', identity_context=None):
        units.append(dict(evidence_id=file['file_id'], evidence_timestamp=file['captured_at'],
                          source_type=Path(file['file_path']).suffix.lstrip('.'),
                          observation_timestamp=observed or file['captured_at'],
                          system_id=system, data_category=category, data=data,
                          resource_id=str(data.get('resource_id', '')), context=context,
                          text=text or json.dumps(data, ensure_ascii=False), source_path='dataset/' + file['file_path'],
                          record_location=location or context, identity_context=identity_context or {}))

    def walk(obj, meta, file, location='$'):
        if isinstance(obj, list):
            for i, item in enumerate(obj):
                walk(item, meta, file, location + '[' + str(i) + ']')
        elif isinstance(obj, dict):
            meta = dict(meta)
            inherited = dict(meta.get('identity_context', {}))
            for key in ('user_id', 'subject_reference', 'customer_reference', 'owner_email'):
                if isinstance(obj.get(key), str) and obj[key]:
                    inherited[key] = obj[key]
            meta['identity_context'] = inherited
            for key in ('system', 'system_id', 'data_store', 'origin_system', 'collection', 'record_type',
                        'data_category', 'collection_name', 'captured_at', 'observed_at', 'recorded_at', 'updated_at'):
                if isinstance(obj.get(key), str):
                    meta[key] = obj[key]
            system = next((meta[k] for k in ('system', 'system_id', 'data_store', 'origin_system') if meta.get(k)), '')
            collection = meta.get('collection', meta.get('collection_name', meta.get('container', '')))
            inferred_system, inferred_category = collection_semantics(collection)
            system = system or inferred_system
            category = meta.get('record_type', meta.get('data_category', inferred_category))
            category = category or SERVICE_COLLECTIONS.get((system, collection), '')
            observed = next((meta[k] for k in ('observed_at', 'recorded_at', 'captured_at', 'updated_at') if meta.get(k)), '')
            if 'resource_id' in obj:
                add(file, obj, system, category, observed, collection, location=location, identity_context=inherited)
                # Preserve nested records only when they declare a distinct resource.
                for key, item in obj.items():
                    if isinstance(item, (dict, list)):
                        walk(item, meta, file, location + '.' + key)
                return
            # Unfiltered collection snapshots, including empty collections, can prove
            # absence of a previously linked resource within this specific snapshot.
            if isinstance(obj.get('records'), list) and obj.get('collection'):
                scopes.append(dict(evidence_id=file['file_id'], evidence_timestamp=file['captured_at'],
                    observation_timestamp=observed or file['captured_at'], system_id=system,
                    data_category=category, resource_ids=[r['resource_id'] for r in obj['records'] if 'resource_id' in r],
                    source_type='json', context=collection))
            for key, item in obj.items():
                if isinstance(item, (dict, list)):
                    child = {**meta, 'container': key}
                    if key.endswith(('_service', '_platform')) or key in ('support_platform', 'account_service'):
                        child['system'] = key
                    walk(item, child, file, location + '.' + key)

    for file in csvs['evidence_files']:
        path = (dataset / file['file_path']).resolve()
        assert path.is_relative_to((dataset / 'evidence').resolve()), 'Evidence path escape'
        ext = path.suffix.lower()
        if ext not in ('.json', '.log', '.txt', '.sql'):
            unsupported.append({**file, 'reason': 'Unsupported structured-baseline format; no PDF/PNG extraction attempted', 'format': ext})
            continue
        try:
            if ext == '.json':
                walk(json.loads(path.read_text()), {}, file)
            elif ext == '.sql':
                conn = sqlite3.connect(':memory:')
                try:
                    conn.set_authorizer(lambda action, a, b, c, d: sqlite3.SQLITE_DENY
                        if action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH) or
                        (action == sqlite3.SQLITE_FUNCTION and str(b).lower() == 'load_extension') else sqlite3.SQLITE_OK)
                    conn.executescript(path.read_text())
                    for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
                        cursor = conn.execute('SELECT * FROM "' + table.replace('"', '""') + '"')
                        fields = [d[0] for d in cursor.description]
                        records = [dict(zip(fields, values)) for values in cursor]
                        system, category = collection_semantics(table)
                        if system and category:
                            scopes.append(dict(evidence_id=file['file_id'], evidence_timestamp=file['captured_at'],
                                observation_timestamp=file['captured_at'], system_id=system, data_category=category,
                                resource_ids=[r['resource_id'] for r in records if 'resource_id' in r],
                                source_type='sql', context=table))
                        # Generic JSON-row replica schemas scope each represented collection.
                        generic = {}
                        for row_no, row in enumerate(records, 1):
                            row_system, row_category = collection_semantics(row.get('collection_name', table))
                            row_system = row.get('origin_system', row_system or system)
                            body = json.loads(row['record_json']) if 'record_json' in row else row
                            if 'resource_id' not in body:
                                continue
                            add(file, body, row_system, row_category or category, file['captured_at'], table,
                                location='table:' + table + '/row:' + str(row_no))
                            if row.get('collection_name'):
                                generic.setdefault((row_system, row_category, row['collection_name']), []).append(body['resource_id'])
                        for (sys, cat, collection), ids in generic.items():
                            scopes.append(dict(evidence_id=file['file_id'], evidence_timestamp=file['captured_at'],
                                observation_timestamp=file['captured_at'], system_id=sys, data_category=cat,
                                resource_ids=ids, source_type='sql', context=table + '/' + collection))
                finally:
                    conn.close()
            else:
                groups = {}
                for i, line in enumerate(path.read_text().splitlines()):
                    match = re.search(r'\b(?:trace_id[=:]"?)?((?:tr-|rb-)[\w-]+)', line)
                    groups.setdefault(match[1] if match else str(i), []).append((i + 1, line))
                for numbered_lines in groups.values():
                    lines = [line for _, line in numbered_lines]
                    text = '\n'.join(lines)
                    data = {}
                    for match in re.finditer(r'\b([a-zA-Z_]+)=(?:"([^"]*)"|([^\s]+))', text):
                        data[match[1]] = decode_value(match[2] if match[2] is not None else match[3])
                    system = str(data.get('service', ''))
                    if not system:
                        systems = re.findall(r'\b[a-z]+_(?:service|platform)\b', text)
                        system = systems[0] if systems else ''
                    category = ''
                    # Pipe-delimited handover records explicitly supply system/category/state.
                    parts = [part.strip() for part in text.split('|')]
                    if len(parts) >= 5 and re.fullmatch(r'[a-z][a-z0-9_]*_\d+', parts[2]):
                        system, category = parts[1], parts[3]
                        data.update(resource_id=parts[2], result=parts[4], subject_reference=parts[5] if len(parts) > 5 else '')
                    dates = [m[0] for line in lines if (m := DATE.match(line.lstrip('- ')))]
                    # A single resource token in a textual record is an exact record reference.
                    # Multiple untyped tokens are indexed as mentions, never merged into one state.
                    if not data.get('resource_id'):
                        tokens = {r for r in RESOURCE.findall(text) if not re.fullmatch(r'(?:user|audit|activity|evidence|case|rule)_\d+', r)}
                        if len(tokens) == 1:
                            data['resource_id'] = next(iter(tokens))
                    add(file, data, system, category, max(dates) if dates else file['captured_at'], text=text,
                        location='lines:' + ','.join(str(n) for n, _ in numbered_lines))
        except (ValueError, sqlite3.Error, OSError) as exc:
            errors.append(dict(evidence_id=file['file_id'], error=str(exc), stage='INGESTION'))
    return {**csvs, 'units': units, 'scopes': scopes, 'unsupported': unsupported, 'parse_errors': errors}


def explicit_resource_links(record, text, primary):
    """Typed participant relationships only; no shared-time/system/ID-pattern joins."""
    keys = {'source_resource_id', 'target_resource_id', 'parent_resource_id', 'account_resource_id',
            'linked_resource_id', 'upstream_resource_id', 'downstream_resource_id'}
    result = set()
    def walk(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in keys and isinstance(value, str) and RESOURCE.fullmatch(value) and value != primary:
                    result.add((primary, value, key))
                if isinstance(value, (dict, list)):
                    walk(value)
        elif isinstance(obj, list):
            for value in obj:
                walk(value)
    walk(record)
    pattern = r'\b(' + '|'.join(sorted(keys)) + r')[=:]"?([a-z][a-z0-9_]*_\d+)\b'
    for match in re.finditer(pattern, text):
        if match[2] != primary:
            result.add((primary, match[2], match[1]))
    for match in re.finditer(r'\b([a-z][a-z0-9_]*_\d+)\s*(?:->|=>)\s*([a-z][a-z0-9_]*_\d+)\b', text):
        if match[1] != match[2]:
            result.add((match[1], match[2], 'explicit_arrow'))
    return [dict(source=a, target=b, relationship=kind) for a, b, kind in sorted(result) if a and b]
