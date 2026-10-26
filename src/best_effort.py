"""Central, explicitly uncertain fallback policy. Never used in strict decisions.
All resource IDs come from existing retrieval. No canonical answer imports.
"""
from copy import deepcopy
from collections import defaultdict
from src.schemas import timestamp
from src.planner import render

LEVEL={'LOW':0,'MEDIUM':1,'HIGH':2}
FAMILY_CATEGORY={'account_':'USER_PROFILE','search_':'SEARCH_INDEX_ENTRY','analytics_':'ANALYTICS_PROFILE',
 'audit_record_':'SECURITY_AUDIT_LOG','tombstone_':'ACCOUNT_TOMBSTONE','backup_':'BACKUP_ARCHIVE',
 'data_flow_':'DATA_FLOW','export_':'USER_EXPORT'}

def confidence(facts,decisions):
    for f in facts:
        if f.get('confidence_level'):continue
        if f.get('discovery_only') or f['state']=='UNKNOWN' or f['source_type']=='activity':
            level,reason='LOW','Resource discovered, but no direct eligible state proof.'
        elif f.get('attribution_confidence')=='TEMPORAL_WORKFLOW':
            level,reason='MEDIUM','Direct state observation; ownership uses provisional unique-account workflow rule, DEV-supported only.'
        else:level,reason='HIGH','Existing exact subject/resource grounding and direct eligible state observation.'
        f.update(confidence_level=level,confidence_reason=reason)
    for d in decisions:
        fs=[f for f in facts if f['resource_id']==d['resource_id'] and f['system_id']==d['system_id']]
        if d.get('unresolved_reason') or not fs:level,reason='LOW',d.get('unresolved_reason') or 'No supporting fact.'
        else:
            weakest=min(fs,key=lambda f:LEVEL[f['confidence_level']]);level,reason=weakest['confidence_level'],weakest['confidence_reason']
        d.update(confidence_level=level,confidence_reason=reason)


def complete(request,identity,facts,decisions,conflicts,retrieval,rules,activities,intent_result,account_fallback=True):
    """Single fallback boundary: strict inputs remain intact in the trace.
    Claims remain claims; assumptions are new LOW-confidence decision annotations.
    """
    facts=deepcopy(facts);decisions=deepcopy(decisions);confidence(facts,decisions)
    assumptions=[];resolved=[];cut=timestamp(request['audit_at'])
    if intent_result['applicable'] is not True or identity.get('conflicts') or not identity.get('user_id'):
        # Never authorize destructive work when intent/identity cannot be established.
        status='NOT_APPLICABLE' if intent_result['applicable'] is False else 'INCOMPLETE'
        return status,[],facts,decisions,[],[dict(type='UNPROVEN_AUTHORIZATION_OR_IDENTITY',confidence_level='LOW',confidence_reason='Required valid status; no resource plan fabricated without authorization/identity.')]
    for d in decisions:
        fs=[f for f in facts if f['resource_id']==d['resource_id'] and f['system_id']==d['system_id']]
        reasons=[];rid=d['resource_id'];category=d['data_category'];state=d['current_state']
        if not category:
            # A contact lookup with explicit opt-in fields is a marketing contact schema,
            # regardless of which service stores it. This is a LOW fallback, not fact.
            if any('contact_lookup_completed' in f.get('source_context','') for f in fs):
                category='MARKETING_PROFILE'
            else:category=next((c for p,c in FAMILY_CATEGORY.items() if rid.startswith(p)),'')
            if category:reasons.append('Category missing: assume conventional resource-family category '+category+'.')
        if not category or category not in rules and category!='DATA_FLOW':
            assumptions.append(dict(resource_id=rid,confidence_level='LOW',confidence_reason='Unknown category; omit unsupported treatment instead of guessing a destructive action.'));continue
        direct=[f for f in fs if f['source_type']!='activity' and f['state']!='UNKNOWN']
        if not state:
            states={f['state'] for f in direct}
            if len(states)==1:state=next(iter(states))
            elif len(states)>1:
                state='ACTIVE' if category in ('DATA_FLOW','BACKUP_ARCHIVE') else 'PRESENT'
                reasons.append('Conflicting direct states: choose noncompliant/risk-present planning assumption; no evidence-precedence claim.')
            elif category=='USER_PROFILE':
                successful=[a for a in activities if a['resource_id']==rid and a['target_system']=='account_service' and a['event_type']=='DELETE_RECORD' and a['reported_result']=='SUCCESS' and timestamp(a['event_time'])<=cut]
                if account_fallback and successful:
                    state='ABSENT';reasons.append('Successful account deletion claim, with no contradictory eligible direct state: assume ABSENT; activity is not trusted proof.')
                else:
                    state='PRESENT';reasons.append('Account state unproven: assume record may remain and propose deletion rather than certify absence.')
            elif fs:
                state='ACTIVE' if category in ('DATA_FLOW','BACKUP_ARCHIVE') else 'PRESENT'
                reasons.append('Grounded record/process without parsed state: assume present/active for protective planning.')
        if not state or not fs:
            assumptions.append(dict(resource_id=rid,confidence_level='LOW',confidence_reason='No state/source basis; omit specific unsupported steps.'));continue
        action=rules[category]['required_action'] if category!='DATA_FLOW' else 'DISABLE_DATA_FLOW'
        target={'DELETE':'ABSENT','REDACT':'REDACTED','ANONYMIZE':'ANONYMIZED','RETAIN':'PRESENT','DISABLE_DATA_FLOW':'DISABLED'}[action]
        if category=='BACKUP_ARCHIVE':target='BLOCKED'
        if category in ('DATA_FLOW','BACKUP_ARCHIVE'):violation=state=='ACTIVE'
        elif action=='DELETE':violation=state!='ABSENT'
        elif action=='RETAIN':violation=False # Do not fabricate a restoration operation.
        else:
            violation=any(f['exposed_fields'] or action=='ANONYMIZE' and f['subject_reference_present'] for f in fs)
            if not violation and not any(f['identifying_fields_observed'] or f['state']==target for f in fs):
                violation=True;reasons.append('Identifier removal unproven: plan policy-preserving redaction/anonymization, not whole-record deletion.')
        if d['unresolved_reason']:
            reasons.append('Unresolved policy condition: '+d['unresolved_reason']+'. Assume supplied category treatment applies; preserve retained records, never infer a missing resource ID.')
        if reasons or conflicts:
            d.update(confidence_level='LOW',confidence_reason=' '.join(reasons) or 'Case contains unresolved conflicting evidence; plan is conditional.')
        d.update(data_category=category,current_state=state,required_action=action,target_state=target,violation=violation,unresolved_reason='')
        d['fallback_assumptions']=reasons
        for f in fs:
            if f['state']=='UNKNOWN':
                f.update(state=state,data_category=category,confidence_level='LOW',confidence_reason=d['confidence_reason'],assumed_state=True,original_state='UNKNOWN',is_direct_state_proof=False)
        if reasons:assumptions.append(dict(resource_id=rid,confidence_level='LOW',confidence_reason=d['confidence_reason']))
        resolved.append(d)
    if not resolved:return 'INCOMPLETE',[],facts,decisions,[],assumptions
    scope_unresolved = len(resolved) != len(decisions) or any(d['required_action']=='RETAIN' and d['current_state']=='ABSENT' for d in resolved)
    status,steps,notes=render(resolved,facts,force_incomplete=scope_unresolved)
    if status=='UNRESOLVED':status,steps='INCOMPLETE',[]
    conf=[]
    for s in steps:
        d=next(d for d in resolved if d['resource_id']==s['resource_id'] and d['system_id']==s['system_id'])
        conf.append(dict(step_no=s['step_no'],confidence_level=d['confidence_level'],confidence_reason=d['confidence_reason']))
    assumptions.append(dict(type='SEARCH_COVERAGE',confidence_level='LOW',confidence_reason='Plan covers grounded resources only. Missing secondary resources are not fabricated; COMPLETE is best-effort over observed scope, not exhaustive proof.'))
    return status,steps,facts,resolved,conf,assumptions+notes
