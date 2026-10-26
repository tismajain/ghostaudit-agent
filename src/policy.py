"""Literal policy treatments with explicit unresolved conditions."""
from collections import defaultdict
from src.schemas import timestamp


def compile_rules(rows):
    result = {}
    for row in rows:
        assert row['required_action'] in ('DELETE', 'REDACT', 'ANONYMIZE', 'RETAIN')
        assert row['data_category'] not in result
        result[row['data_category']] = row
    return result


def apply(facts, rules, request):
    grouped = defaultdict(list)
    for fact in facts:
        grouped[(fact['system_id'], fact['resource_id'])].append(fact)
    decisions = []
    for (system, resource), observations in sorted(grouped.items()):
        categories = {f['data_category'] for f in observations if f['data_category']}
        states = {f['state'] for f in observations if f['state'] != 'UNKNOWN'}
        decision = dict(system_id=system, resource_id=resource, data_category='', required_action='',
                        current_state='', target_state='', violation=False, unresolved_reason='',
                        evidence_ids=sorted({f['evidence_id'] for f in observations}), rule_id='', condition='')
        # Preserve known category/action independently of state observability.
        if len(categories) == 1:
            known_category = next(iter(categories))
            known_rule = rules.get(known_category)
            decision['data_category'] = known_category
            if known_rule:
                decision.update(required_action=known_rule['required_action'], rule_id=known_rule['rule_id'], condition=known_rule['condition'])
        if len(categories) != 1 or len(states) != 1:
            decision['unresolved_reason'] = 'Missing/contradictory category or observed state'
            decisions.append(decision)
            continue
        category, state = next(iter(categories)), next(iter(states))
        decision.update(data_category=category, current_state=state)
        if category == 'DATA_FLOW':
            decision.update(required_action='DISABLE_DATA_FLOW', target_state='DISABLED', violation=state == 'ACTIVE')
            if state not in ('ACTIVE', 'DISABLED'):
                decision['unresolved_reason'] = 'Flow enabled state unknown'
            decisions.append(decision)
            continue
        rule = rules.get(category)
        if not rule:
            decision['unresolved_reason'] = 'No policy for observed category'
            decisions.append(decision)
            continue
        action = rule['required_action']
        decision.update(required_action=action, rule_id=rule['rule_id'], condition=rule['condition'])
        conditions = [f['condition_facts'] for f in observations if f.get('condition_facts')]
        if category == 'BACKUP_ARCHIVE':
            decision.update(target_state='BLOCKED', violation=state == 'ACTIVE')
            if state not in ('ACTIVE', 'BLOCKED'):
                decision['unresolved_reason'] = 'Restore accessibility unknown; do not delete the archive'
        elif action == 'DELETE':
            decision.update(target_state='ABSENT', violation=state != 'ABSENT')
            if category == 'SUPPORT_ATTACHMENT' and not any(c.get('attachment_subject_only') is True for c in conditions):
                decision['unresolved_reason'] = 'Subject-only attachment ownership not established'
        elif action in ('REDACT', 'ANONYMIZE'):
            target = 'REDACTED' if action == 'REDACT' else 'ANONYMIZED'
            identifying = any(f['exposed_fields'] or (action == 'ANONYMIZE' and f['subject_reference_present']) for f in observations)
            inspected = any(f['identifying_fields_observed'] for f in observations)
            explicit = any(c.get('explicit_result') == target for c in conditions)
            decision.update(target_state=target, violation=identifying)
            if state == 'ABSENT':
                decision['unresolved_reason'] = 'Policy-preserved/anonymized resource absent; missing-record repair is not specified'
            elif not identifying and not inspected and not explicit:
                decision['unresolved_reason'] = 'Identifier removal cannot be verified from observed fields'
            if category == 'ACCOUNT_TOMBSTONE' and not any(c.get('tombstone_condition') for c in conditions):
                decision['unresolved_reason'] = 'Deleted account and permitted stable-reference tombstone condition not established'
            if category == 'SUPPORT_MESSAGE' and not any(c.get('shared_context') is True or
                    any(word in c.get('record_context', '').lower() for word in ('order', 'delivery', 'agent', 'shared', 'customer')) for c in conditions):
                decision['unresolved_reason'] = 'Shared support-context policy condition not established'
        else:
            decision.update(target_state='PRESENT', violation=state == 'ABSENT')
            if state == 'ABSENT':
                decision['unresolved_reason'] = 'Required retained record missing; no allowed restoration operation specified'
            if category == 'SECURITY_AUDIT_LOG':
                within_period = any((c.get('retention_until') and
                                    timestamp(c['retention_until']) >= timestamp(request['audit_at'])) for c in conditions)
                if not within_period:
                    decision['unresolved_reason'] = 'Security retention-period condition not established'
            if category == 'LEGAL_HOLD_RECORD' and not any(c.get('legal_hold_active') is True for c in conditions):
                decision['unresolved_reason'] = 'Active legal hold not established'
        decisions.append(decision)
    return decisions
