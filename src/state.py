"""Cutoff-safe observation extraction. Conflicting observations are not ranked."""
import json
import re
from collections import defaultdict
from dataclasses import asdict

from src.identity import exact_contains, match, ownership
from src.ingest import RESOURCE, explicit_resource_links
from src.schemas import Fact, timestamp
from src.temporal import account_workflow_candidate

EVENT_CATEGORIES = {
    'profile_lookup': 'USER_PROFILE', 'index_query': 'SEARCH_INDEX_ENTRY',
    'analytics_profile': 'ANALYTICS_PROFILE', 'audit_record': 'SECURITY_AUDIT_LOG',
    'support_ticket': 'SUPPORT_MESSAGE', 'message_pii_scan': 'SUPPORT_MESSAGE',
    'attachment_pii_scan': 'SUPPORT_ATTACHMENT', 'connector_config': 'DATA_FLOW',
    'connector_heartbeat': 'DATA_FLOW', 'restore_policy': 'BACKUP_ARCHIVE',
    'export_metadata': 'USER_EXPORT', 'export_download': 'USER_EXPORT',
}
DIRECT_FIELDS = {
    'name', 'full_name', 'display_name', 'email', 'phone', 'email_hash',
    'requester_name', 'requester_email', 'requester_phone', 'customer_email',
    'owner_email', 'owner_phone', 'matched_value', 'correlation_key',
}
REFERENCE_FIELDS = {'user_id', 'customer_reference', 'subject_reference'}


def available(item, cutoff):
    return timestamp(item['evidence_timestamp']) <= cutoff and timestamp(item['observation_timestamp']) <= cutoff


def fields(data):
    result = []
    if isinstance(data, dict):
        for key, value in data.items():
            result.append((key, value))
            if isinstance(value, (dict, list)):
                result.extend(fields(value))
    elif isinstance(data, list):
        for value in data:
            result.extend(fields(value))
    return result


def boolean(value):
    if value in (True, 1, '1', 'true'):
        return True
    if value in (False, 0, '0', 'false'):
        return False
    return None


def observe(unit, identity):
    data, text = unit['data'], unit['text']
    values = dict(fields(data))
    category = unit['data_category']
    event = str(values.get('event', ''))
    if not category:
        category = next((cat for key, cat in EVENT_CATEGORIES.items() if key in event), '')
    if not category:
        category_match = re.search(r'\b(?:record_type|data_category)[=:]"?([A-Z_]+)', text)
        if category_match:
            category = category_match[1]
    result = str(values.get('result', '')).upper()
    state = 'UNKNOWN'
    status = str(values.get('http_status', values.get('status_code', '')))
    if result in ('NOT_FOUND', 'ABSENT') or status == '404' or str(values.get('rows', '')) == '0':
        state = 'ABSENT'
    elif result in ('FOUND', 'PRESENT', 'RETAINED', 'IDENTIFIABLE', 'REDACTED', 'ANONYMIZED', 'ACTIVE', 'DISABLED', 'BLOCKED'):
        state = 'PRESENT'
    elif status == '200' or str(values.get('rows', '')).isdigit() and int(values['rows']) > 0:
        state = 'PRESENT'
    elif unit['source_type'] in ('json', 'sql') and data.get('resource_id'):
        state = 'PRESENT'
    if state == 'UNKNOWN' and event.endswith('_read_completed') and any(
            key in values for key in ('email', 'requester_email', 'audience_cohort', 'retention_until', 'object_key')):
        state = 'PRESENT'
    if isinstance(data.get('hits'), dict):
        total = data['hits'].get('total')
        if total is not None:
            state = 'ABSENT' if total == 0 else 'PRESENT'
    if values.get('result') in ('hit', 'miss'):
        state = 'PRESENT' if values['result'] == 'hit' else 'ABSENT'
    enabled = boolean(values.get('enabled'))
    restore_allowed = boolean(values.get('restore_allowed'))
    if category == 'DATA_FLOW':
        if enabled is not None:
            state = 'ACTIVE' if enabled else 'DISABLED'
        elif result in ('ACTIVE', 'DISABLED'):
            state = result
    if category == 'BACKUP_ARCHIVE':
        if restore_allowed is not None:
            state = 'ACTIVE' if restore_allowed else 'BLOCKED'
        elif result in ('ACTIVE', 'BLOCKED'):
            state = result
    pairs = fields(data)
    exposed = []
    observed = False
    reference = False
    for key, value in pairs:
        if key in DIRECT_FIELDS and key not in ('correlation_key', 'matched_value'):
            observed = True
            if value not in (None, '') and not isinstance(value, (dict, list)):
                exposed.append(key)
        if key in REFERENCE_FIELDS and (value == identity['user_id'] or
                category in ('ANALYTICS_PROFILE', 'PRODUCT_TELEMETRY') and value not in (None, '')):
            reference = True
        if key in ('matched_value', 'message_excerpt', 'message_text', 'message', 'body', 'correlation_key') and isinstance(value, str) and match(value, identity):
            # A hash/user-reference used to query a lookup is not an exposed row field.
            if key not in ('correlation_key',) or 'contact_lookup_completed' in event:
                exposed.append(key)
    if 'pii_scan' in event or 'identity_scan' in event:
        if match(text, identity):
            exposed.append('matched_identifier_in_scan')
            state = 'PRESENT'
    if result == 'IDENTIFIABLE':
        exposed.append('explicit_identifiable_result')
        observed = True
    if result in ('REDACTED', 'ANONYMIZED'):
        observed = True
    # A retained support reference is permitted; direct contact fields must all be
    # explicitly inspected. Missing keys alone never prove removal.
    required = ({'requester_name', 'requester_email', 'requester_phone'}
                if category == 'SUPPORT_MESSAGE' else
                {'name', 'email', 'phone', 'email_hash'} if category == 'ACCOUNT_TOMBSTONE' else set())
    complete_nulls = bool(required) and required <= values.keys() and all(values[k] in (None, '') for k in required)
    tombstone_condition = values.get('account_status') == 'DELETED' and reference
    if state == 'PRESENT' and not exposed:
        if category == 'SUPPORT_MESSAGE' and complete_nulls:
            state = 'REDACTED'
        elif category == 'ACCOUNT_TOMBSTONE' and complete_nulls and tombstone_condition:
            state = 'REDACTED'
        elif result in ('REDACTED', 'ANONYMIZED'):
            if result != 'ANONYMIZED' or not reference:
                state = result
    conditions = {
        'tombstone_condition': tombstone_condition,
        'complete_direct_fields_inspected': complete_nulls,
        'explicit_result': result,
        'retention_until': values.get('retention_until', values.get('retain_until', values.get('retained_until', ''))),
        'legal_hold_active': values.get('legal_hold_active'),
        'shared_context': values.get('shared_context'),
        'record_context': str(values.get('message_excerpt', '')),
        'attachment_subject_only': values.get('subject_only', values.get('attachment_subject_only')),
        'restore_allowed': restore_allowed,
        'retained_claim': result == 'RETAINED',
    }
    return category, state, sorted(set(exposed)), observed, reference, conditions


def discover(request, identity, data):
    """Subject-bound resource discovery with a strict cutoff and explicit edges only."""
    cutoff = timestamp(request['audit_at'])
    units = [u for u in data['units'] if available(u, cutoff)]
    activities = [a for a in data['system_activity'] if timestamp(a['event_time']) <= cutoff]
    selected, resources, direct, provenance = {}, {}, {}, defaultdict(list)
    conflicts, activity_links = [], []

    def own_unit(unit):
        text = unit['text'] + '\n' + json.dumps(unit.get('identity_context', {}), ensure_ascii=False)
        other = set(re.findall(r'\buser_\d+\b', text)) - {identity['user_id']}
        return not other or exact_contains(text, identity['user_id']), text

    def admit(rid, identifier, source, route, from_resource='', relationship=''):
        if not rid:
            return
        resources.setdefault(rid, identifier)
        proof = dict(source_id=source, route=route, matched_identifier=identifier,
                     from_resource=from_resource, relationship=relationship)
        if proof not in provenance[rid]:
            provenance[rid].append(proof)

    for i, unit in enumerate(units):
        owned, text = own_unit(unit)
        matched = match(text, identity)
        if matched and owned and unit['resource_id']:
            selected[i] = matched
            direct[unit['resource_id']] = matched
            admit(unit['resource_id'], matched, unit['evidence_id'], 'direct_identifier')
        elif matched and not owned:
            conflicts.append(dict(type='RESOURCE_OWNER_CONFLICT', resource_id=unit['resource_id'], evidence_id=unit['evidence_id']))
    for activity in activities:
        matched = match(json.dumps(activity, ensure_ascii=False), identity)
        if matched:
            direct[activity['resource_id']] = matched
            admit(activity['resource_id'], matched, activity['activity_id'], 'direct_activity_identifier')
    # Build adjacency only from explicitly declared resource relationships.
    edges = []
    for i, unit in enumerate(units):
        owned, text = own_unit(unit)
        if owned:
            for edge in explicit_resource_links(unit['data'], text, unit['resource_id']):
                edges.append({**edge, 'source_id': unit['evidence_id'], 'kind': 'evidence_relationship'})
    for activity in activities:
        for edge in explicit_resource_links(activity, activity['details'], activity['resource_id']):
            edges.append({**edge, 'source_id': activity['activity_id'], 'kind': 'activity_relationship'})
    changed = True
    while changed:
        old = len(resources)
        for edge in edges:
            for source, target in ((edge['source'], edge['target']), (edge['target'], edge['source'])):
                if source in resources:
                    admit(target, resources[source], edge['source_id'], edge['kind'], source, edge['relationship'])
        for i, unit in enumerate(units):
            if unit['resource_id'] in resources and own_unit(unit)[0]:
                selected.setdefault(i, resources[unit['resource_id']])
        changed = old != len(resources)
    # This one account-only rule passed DEV precision and all-request collision checks.
    # It runs after identity discovery and never expands unrelated temporal families.
    temporal = account_workflow_candidate(request, data['system_activity'])
    temporal_attributions = {}
    candidate = temporal['selected_resource_id']
    if candidate:
        known_accounts = {rid for rid in resources if rid.startswith('account_')}
        if candidate in known_accounts:
            temporal['decision'] = 'ALREADY_IDENTITY_GROUNDED'
        elif known_accounts:
            temporal['decision'] = 'REJECT_COMPETING_IDENTITY_ACCOUNT'
            temporal['higher_confidence_account_ids'] = sorted(known_accounts)
        else:
            if '_identifier_owners' not in data:
                data['_identifier_owners'] = ownership(data.get('user_identities', []), data.get('user_audit_log', []))[0]
            owner_map = data['_identifier_owners']
            foreign = []
            owner_keys = {'user_id', 'customer_reference', 'subject_reference', 'subject_ref', 'email', 'phone',
                          'email_hash', 'owner_email', 'customer_email', 'requester_email', 'lookup_key', 'scan_key'}
            for unit in units:
                if unit['resource_id'] != candidate:
                    continue
                claims = set()
                for key, value in fields({**unit.get('identity_context', {}), **unit['data']}):
                    if key not in owner_keys or not isinstance(value, str) or not value:
                        continue
                    if re.fullmatch(r'user_\d+', value):
                        claims.add(value)
                    else:
                        observed_owners = owner_map.get(value.strip().casefold(), set())
                        if len(observed_owners) == 1:
                            claims.update(observed_owners)
                if claims - {identity['user_id']}:
                    foreign.append(dict(evidence_id=unit['evidence_id'], user_ids=sorted(claims)))
            if foreign:
                temporal['decision'] = 'REJECT_IDENTITY_EVIDENCE_CONFLICT'
                temporal['conflicting_owner_proofs'] = foreign
            else:
                temporal['decision'] = 'ATTRIBUTED'
                temporal['attributed_user_id'] = identity['user_id']
                temporal['subject_anchor'] = dict(request_email=request['email'], user_id=identity['user_id'])
                temporal_attributions[candidate] = temporal
                # Empty matched_identifier is deliberate: the event contains no exact subject proof.
                admit(candidate, '', temporal['events'][0]['activity_id'], 'TEMPORAL_WORKFLOW')
                provenance[candidate][-1].update(temporal)
                for i, unit in enumerate(units):
                    if unit['resource_id'] == candidate and own_unit(unit)[0]:
                        selected.setdefault(i, match(own_unit(unit)[1], identity))
    for activity in activities:
        rid = activity['resource_id']
        if rid in resources:
            activity_links.append(dict(activity_id=activity['activity_id'], resource_id=rid,
                matched_identifier=resources[rid], used_as_state_proof=False))
    return dict(units=units, selected=selected, resources=resources, direct=direct,
                provenance=dict(provenance), conflicts=conflicts, activity_links=activity_links,
                activities=activities, ignored_later_units=len(data['units'])-len(units),
                temporal_workflow=temporal, temporal_attributions=temporal_attributions)


def extract(request, identity, data):
    cutoff = timestamp(request['audit_at'])
    conflicts = list(identity['conflicts'])
    if not identity['user_id']:
        return [], conflicts, {'linked_resources_without_state': [], 'ignored_later_units': 0}
    discovery = discover(request, identity, data)
    units, selected, resources = discovery['units'], discovery['selected'], discovery['resources']
    conflicts.extend(discovery['conflicts'])
    later_count, links = discovery['ignored_later_units'], discovery['activity_links']
    facts = []
    resource_meta = defaultdict(set)
    for i, matched in sorted(selected.items()):
        unit = units[i]
        category, state, exposed, observed, reference, conditions = observe(unit, identity)
        if state == 'UNKNOWN' and not category:
            # Keep unknown observations in facts for an explicit unresolved decision.
            pass
        system = unit['system_id']
        if not system:
            conflicts.append({'type': 'MISSING_SYSTEM_METADATA', 'resource_id': unit['resource_id'], 'evidence_id': unit['evidence_id']})
        fact = Fact(request['case_id'], system, unit['resource_id'], category, state, matched,
                    unit['evidence_id'], unit['evidence_timestamp'], unit['source_type'],
                    unit['observation_timestamp'], exposed, observed, reference, conditions, unit['context'])
        facts.append(asdict(fact))
        resource_meta[unit['resource_id']].add((system, category))
    # For activity-linked accounts absent from all observed rows, scope can supply proof.
    for activity in data['system_activity']:
        if activity['resource_id'] in resources and timestamp(activity['event_time']) <= cutoff:
            if activity['target_system'] == 'account_service':
                resource_meta[activity['resource_id']].add(('account_service', 'USER_PROFILE'))
    same_file_resources = {(units[i]['evidence_id'], units[i]['resource_id']) for i in selected}
    for scope in data['scopes']:
        if not available(scope, cutoff):
            continue
        for rid, matched in sorted(resources.items()):
            # A bundle/table for unrelated subjects is not an exhaustive global absence proof.
            # Only compare sibling snapshot tables when this exact resource is present
            # elsewhere in the same artifact. No cross-file absence extrapolation.
            if (scope['evidence_id'], rid) not in same_file_resources:
                continue
            if (scope['system_id'], scope['data_category']) not in resource_meta[rid] or rid in scope['resource_ids']:
                continue
            if scope['data_category'] == 'DATA_FLOW' or not scope['data_category']:
                continue
            fact = Fact(request['case_id'], scope['system_id'], rid, scope['data_category'], 'ABSENT', matched,
                        scope['evidence_id'], scope['evidence_timestamp'], scope['source_type'],
                        scope['observation_timestamp'], source_context=scope['context'])
            facts.append(asdict(fact))
    observed_ids = {f['resource_id'] for f in facts}
    for activity in discovery['activities']:
        rid = activity['resource_id']
        if rid not in resources or rid in observed_ids:
            continue
        fact = asdict(Fact(request['case_id'], activity['target_system'], rid, '', 'UNKNOWN', resources[rid],
            activity['activity_id'], activity['event_time'], 'activity', activity['event_time'],
            source_context='Discovery-only explicit resource link; activity outcome is not state proof'))
        fact['discovery_only'] = True
        facts.append(fact)
        observed_ids.add(rid)
    for fact in facts:
        if fact['resource_id'] in discovery['temporal_attributions']:
            fact['attribution_confidence'] = 'TEMPORAL_WORKFLOW'
            fact['attribution_provenance'] = discovery['temporal_attributions'][fact['resource_id']]
            if fact['source_type'] == 'activity':
                fact['source_context'] = 'Temporal workflow attribution only; operation result is not state proof'
    # Do not choose a latest/source-priority winner. All incompatible observations remain visible.
    grouped = defaultdict(list)
    for fact in facts:
        grouped[(fact['system_id'], fact['resource_id'])].append(fact)
    for (system, rid), observations in sorted(grouped.items()):
        states = {f['state'] for f in observations if f['state'] != 'UNKNOWN'}
        exposures = {bool(f['exposed_fields']) for f in observations if f['identifying_fields_observed'] and f['state'] != 'ABSENT'}
        if len(states) > 1 or len(exposures) > 1:
            conflicts.append({'type': 'OBSERVATION_CONFLICT', 'system_id': system, 'resource_id': rid,
                              'states': sorted(states), 'exposure_variants': sorted(exposures),
                              'evidence_ids': sorted({f['evidence_id'] for f in observations}),
                              'resolution': 'UNRESOLVED; no evidence precedence rule'})
    known = {f['resource_id'] for f in facts if f['state'] != 'UNKNOWN'}
    missing = sorted(set(resources) - known)
    return facts, conflicts, dict(linked_resources_without_state=missing,
        resource_links_from_activity=links, ignored_later_units=later_count,
        discovered_resources=sorted(resources), direct_identifier_resources=sorted(discovery['direct']),
        resource_discovery_provenance=discovery['provenance'], temporal_workflow=discovery['temporal_workflow'],
        temporal_attributions=discovery['temporal_attributions'], cutoff_interpretation='Exclude post-audit evidence from both discovery and state.',
        facts_available_at_cutoff=all(timestamp(f['evidence_timestamp']) <= cutoff and
                                     timestamp(f['observation_timestamp']) <= cutoff for f in facts))
