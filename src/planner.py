"""Challenge-ordered steps for all established policy-relevant resource facts."""
from src.schemas import OP_STATE, step_key

VERIFY = {'ABSENT': 'VERIFY_RECORD_ABSENT', 'PRESENT': 'VERIFY_RECORD_PRESENT',
          'REDACTED': 'VERIFY_RECORD_REDACTED', 'ANONYMIZED': 'VERIFY_RECORD_ANONYMIZED',
          'DISABLED': 'VERIFY_DATA_FLOW_DISABLED', 'BLOCKED': 'VERIFY_RESTORE_BLOCKED'}
REPAIR = {'DELETE': ('REPORT_REMAINING_RECORD', 'DELETE_RECORD'),
          'REDACT': ('REPORT_EXPOSED_PII', 'REDACT_RECORD'),
          'ANONYMIZE': ('REPORT_EXPOSED_PII', 'ANONYMIZE_RECORD'),
          'DISABLE_DATA_FLOW': ('REPORT_ACTIVE_DATA_FLOW', 'DISABLE_DATA_FLOW')}


def plan(decisions, facts, conflicts, retrieval):
    reasons = list(conflicts)
    reasons.extend({'type': 'POLICY_UNRESOLVED', 'resource_id': d['resource_id'], 'reason': d['unresolved_reason']}
                   for d in decisions if d['unresolved_reason'])
    if retrieval['linked_resources_without_state']:
        reasons.append({'type': 'RETRIEVAL_GAP', 'resource_ids': retrieval['linked_resources_without_state']})
    if not any(d['data_category'] == 'USER_PROFILE' for d in decisions):
        reasons.append({'type': 'ACCOUNT_STATE_UNESTABLISHED'})
    if not decisions:
        reasons.append({'type': 'NO_POLICY_DECISIONS'})
    if reasons:
        # Diagnostic abstention, deliberately not a challenge submission status.
        return 'UNRESOLVED', [], reasons
    return render(decisions, facts)


def render(decisions, facts, force_incomplete=False):
    """Shared serializer; best-effort supplies separately annotated decisions."""
    incomplete = force_incomplete or any(d['violation'] for d in decisions)
    steps, ambiguities = [], []

    def add(phase, operation, decision, evidence=''):
        steps.append(dict(step_no=0, phase=phase, system_id=decision['system_id'], resource_id=decision['resource_id'],
                          operation=operation, state=OP_STATE[operation], evidence_id=evidence))

    for decision in decisions:
        ids = sorted({f['evidence_id'] for f in facts if f['system_id'] == decision['system_id'] and
                      f['resource_id'] == decision['resource_id'] and f['state'] != 'UNKNOWN'})
        if not ids:
            return 'UNRESOLVED', [], [{'type': 'NO_SUPPORTING_CITATION', 'resource_id': decision['resource_id']}]
        if len(ids) > 1:
            ambiguities.append({'type': 'EQUIVALENT_CITATION_CHOICES', 'resource_id': decision['resource_id'],
                                'evidence_ids': ids, 'note': 'Lexical serialization tie-break among agreeing observations; no state/source precedence.'})
        evidence = ids[0]
        if decision['violation']:
            if decision['data_category'] == 'BACKUP_ARCHIVE':
                finding, repair = 'REPORT_RESTORE_RISK', 'BLOCK_RESTORE'
            else:
                finding, repair = REPAIR[decision['required_action']]
            add('FINDING', finding, decision, evidence)
            add('REMEDIATION', repair, decision)
        # Confirmed breadth: also verify already-correct, retained and absent-account resources.
        add('VERIFICATION', VERIFY[decision['target_state']], decision, '' if incomplete else evidence)
    steps.sort(key=step_key)
    for i, step in enumerate(steps, 1):
        step['step_no'] = i
    return 'INCOMPLETE' if incomplete else 'COMPLETE', steps, ambiguities
