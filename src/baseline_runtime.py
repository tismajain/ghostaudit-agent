"""Shared frozen best-effort case execution, selected by request input rather than case IDs."""
from src.identity import resolve
from src.planner import plan
from src.policy import apply,compile_rules
from src.schemas import timestamp
from src.state import extract
from src.best_effort import complete,confidence
from src.intent import intent

def baseline_case(request,data,labels):
    case=request['case_id']
    rules=compile_rules(data['deletion_rules'])
    intent_result = intent(request, labels)
    identity = resolve(request, data['user_identities'], data['user_audit_log'])
    facts, conflicts, retrieval = [], [], {'linked_resources_without_state': []}
    decisions, steps, planner_notes = [], [], []
    if intent_result['applicable'] is False:
        status = 'NOT_APPLICABLE'
    elif intent_result['applicable'] is None:
        status = 'UNRESOLVED'
        conflicts.append({'type': 'INTENT_UNRESOLVED', 'reason': intent_result['reason']})
    elif identity['conflicts']:
        status = 'UNRESOLVED'
        conflicts.extend(identity['conflicts'])
    else:
        facts, conflicts, retrieval = extract(request, identity, data)
        decisions = apply(facts, rules, request)
        status, steps, planner_notes = plan(decisions, facts, conflicts, retrieval)
    strict_status = status
    confidence(facts, decisions)
    step_confidence = []
    fallback_notes = []
    if 'best_effort' == 'best_effort':
        status, steps, facts, decisions, step_confidence, fallback_notes = complete(
            request, identity, facts, decisions, conflicts, retrieval, rules, data['system_activity'],
            intent_result, account_fallback=True)
        assert status in ('COMPLETE','INCOMPLETE','NOT_APPLICABLE')
    else:
        for step in steps:
            decision = next(d for d in decisions if d['resource_id']==step['resource_id'] and d['system_id']==step['system_id'])
            step_confidence.append(dict(step_no=step['step_no'],confidence_level=decision['confidence_level'],confidence_reason=decision['confidence_reason']))
    resource_confidence = {}
    for rid in set(retrieval.get('discovered_resources', [])) | {f['resource_id'] for f in facts}:
        supporting = [x for x in facts + decisions if x['resource_id']==rid]
        if supporting:
            weakest = min(supporting, key=lambda x: {'LOW':0,'MEDIUM':1,'HIGH':2}[x['confidence_level']])
            resource_confidence[rid] = dict(confidence_level=weakest['confidence_level'],confidence_reason=weakest['confidence_reason'])
        else:
            resource_confidence[rid] = dict(confidence_level='LOW',confidence_reason='Discovered resource without state/policy proof.')
    trace = dict(resource_confidence=resource_confidence, mode='best_effort', strict_status=strict_status, step_confidence=step_confidence,
                 fallback_notes=fallback_notes, request=request, intent=intent_result, resolved_identity=identity, facts=facts,
                 conflicts=conflicts, retrieval=retrieval, policy_decisions=decisions,
                 generated_steps=steps, final_status=status, planner_notes=planner_notes,
                 unsupported_evidence=[{**u, 'relevance': 'unknown; contents not inspected'} for u in data['unsupported']
                                       if timestamp(u['captured_at']) <= timestamp(request['audit_at'])],
                 ingestion_errors=data['parse_errors'])
    return trace
