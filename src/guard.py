"""Independent atomic-evidence verification. Never trusts model-provided facts."""
import json,re
from pathlib import Path
from src.identity import match,exact_contains
from src.state import observe,available
from src.policy import apply,compile_rules
from src.schemas import OP_STATE,timestamp
from src.planner import VERIFY,REPAIR

STEP_FIELDS={'step_no','phase','system_id','resource_id','operation','state','evidence_id'}
FINDING_TYPES={'RESOURCE_OWNERSHIP','RESOURCE_STATE','EXPOSED_PII','ACTIVE_DATA_FLOW','RESTORE_RISK','POLICY_CONDITION'}
def semantic(step):return tuple(step[k] for k in ('phase','operation','system_id','resource_id','state','evidence_id'))


def _flat_fields(value):
    """Return exact dotted paths and keys from one atomic participant record."""
    found={}
    def walk(item,prefix=''):
        if isinstance(item,dict):
            for key,val in item.items():
                path=f'{prefix}.{key}' if prefix else key
                found[path]=val
                if isinstance(val,(dict,list)):walk(val,path)
        elif isinstance(item,list):
            for i,val in enumerate(item):
                path=f'{prefix}[{i}]'
                if isinstance(val,(dict,list)):walk(val,path)
    walk(value)
    return found


def _atomic_owner(unit, identity):
    raw=json.dumps(unit.get('data',{}),ensure_ascii=False)
    other=set(re.findall(r'\buser_\d+\b',raw))-{identity.get('user_id','')}
    return bool(match(raw,identity)) and not other


def _relationship_edges(tools):
    """Extract only explicit typed resource references from eligible participant rows."""
    from src.ingest import explicit_resource_links
    edges=[]
    for unit in tools.data['units']:
        if timestamp(unit['evidence_timestamp'])>tools.cut or timestamp(unit['observation_timestamp'])>tools.cut:
            continue
        for edge in explicit_resource_links(unit['data'],unit.get('text',''),unit.get('resource_id','')):
            edges.append({'source':edge['source'],'target':edge['target'],'relationship':edge['relationship'],
                          'evidence_id':unit['evidence_id'],'timestamp':unit['observation_timestamp'],
                          'record_location':unit['record_location']})
    for event in tools.data['system_activity']:
        if timestamp(event['event_time'])>tools.cut:continue
        for edge in explicit_resource_links(event,event.get('details',''),event.get('resource_id','')):
            edges.append({'source':edge['source'],'target':edge['target'],'relationship':edge['relationship'],
                          'evidence_id':event['activity_id'],'timestamp':event['event_time'],
                          'record_location':'system_activity:'+event['activity_id']})
    return edges


def _ownership_path(resource_id, evidence_id, tools):
    identity=tools.trace.get('resolved_identity',{})
    if not identity.get('user_id') or identity.get('conflicts'):
        return None
    direct=[]
    for unit in tools.data['units']:
        if unit.get('resource_id')==resource_id and unit.get('evidence_id')==evidence_id:
            if timestamp(unit['evidence_timestamp'])<=tools.cut and timestamp(unit['observation_timestamp'])<=tools.cut and _atomic_owner(unit,identity):
                direct.append(unit)
    if direct:
        return {'kind':'ATOMIC_IDENTIFIER', 'path':[], 'unit':direct[0]}
    # Previously validated HIGH deterministic facts form permitted graph anchors.
    anchors={f['resource_id'] for f in tools.trace.get('facts',[]) if f.get('confidence_level')=='HIGH'}
    for unit in tools.data['units']:
        if timestamp(unit['evidence_timestamp'])<=tools.cut and timestamp(unit['observation_timestamp'])<=tools.cut and _atomic_owner(unit,identity) and unit.get('resource_id'):
            anchors.add(unit['resource_id'])
    edges=_relationship_edges(tools)
    queue=[(anchor,[]) for anchor in sorted(anchors)]
    seen=set(anchors)
    while queue:
        current,path=queue.pop(0)
        if current==resource_id:
            target_units=[u for u in tools.data['units'] if u.get('resource_id')==resource_id and u.get('evidence_id')==evidence_id and
                          timestamp(u['evidence_timestamp'])<=tools.cut and timestamp(u['observation_timestamp'])<=tools.cut]
            if target_units:return {'kind':'EXPLICIT_RELATION_CHAIN','path':path,'unit':target_units[0]}
        if len(path)>=3:continue
        for edge in edges:
            other=edge['target'] if edge['source']==current else edge['source'] if edge['target']==current else None
            if other and other not in seen:
                seen.add(other);queue.append((other,path+[edge]))
    return None


def validate_findings(findings,tools):
    """Independently validate typed agent claims and return only grounded facts."""
    results=[];facts=[]
    if not isinstance(findings,list):
        return {'results':[{'status':'REJECTED','reason':'findings must be a list'}], 'validated_facts':[]}
    for index,finding in enumerate(findings):
        def finish(status,reason,**extra):
            results.append({'finding_index':index,'finding':finding,'status':status,'reason':reason,**extra})
        required={'type','system_id','resource_id','evidence_id','data_category','state','supporting_observation'}
        if not isinstance(finding,dict) or set(finding)!=required or finding.get('type') not in FINDING_TYPES:
            finish('REJECTED','Invalid typed-finding schema.');continue
        rid,eid=finding.get('resource_id'),finding.get('evidence_id')
        if not isinstance(rid,str) or not re.fullmatch(r'[a-z][a-z0-9_]*_\d+',rid) or not isinstance(eid,str) or not eid:
            finish('REJECTED','Resource/evidence IDs must be literal participant IDs.');continue
        if eid not in tools.manifest or eid not in tools.allowed:
            finish('REJECTED','Evidence was not returned by candidate listing or exact search.');continue
        if eid not in tools.inspected:
            finish('UNVERIFIABLE','Evidence must be inspected before a finding is validated.');continue
        manifest=tools.manifest[eid]
        if timestamp(manifest['captured_at'])>tools.cut:
            finish('REJECTED','Evidence capture is after audit_at.');continue
        observation=finding.get('supporting_observation')
        if not isinstance(observation,dict):
            finish('REJECTED','supporting_observation must be an object.');continue
        path=_ownership_path(rid,eid,tools)
        if not path:
            finish('UNVERIFIABLE','No exact subject identifier in the same atomic record and no validated explicit relationship path.');continue
        unit=path['unit'];data=unit.get('data',{});flat=_flat_fields(data)
        claimed_location=observation.get('record_location')
        if claimed_location and claimed_location!=unit.get('record_location'):
            finish('REJECTED','record_location does not match the inspected atomic record.');continue
        literal=observation.get('literal_fields',[])
        if not isinstance(literal,list) or any(not isinstance(x,dict) or set(x)!={'field','value'} for x in literal):
            finish('REJECTED','literal_fields must be an array of {field,value} pairs.');continue
        if any(x['field'] not in flat or str(flat[x['field']])!=str(x['value']) for x in literal):
            finish('REJECTED','One or more claimed literal field values are not present in the atomic record.');continue
        category,state,exposed,inspected,reference,conditions=observe(unit,tools.trace['resolved_identity'])
        declared_category=finding.get('data_category') or ''
        if declared_category and category!=declared_category:
            finish('REJECTED','Declared data_category differs from deterministic schema observation.',observed_category=category);continue
        declared_state=finding.get('state') or ''
        if declared_state and state!=declared_state:
            finish('REJECTED','Declared state differs from deterministic field extraction.',observed_state=state);continue
        ftype=finding['type']
        if ftype=='RESOURCE_OWNERSHIP':
            validated={'case_id':tools.case_id,'system_id':unit['system_id'] or finding['system_id'],'resource_id':rid,
                       'data_category':category,'state':state,'evidence_id':eid,
                       'ownership_provenance':path['kind'],'relationship_path':path['path'],
                       'record_location':unit['record_location'],'confidence_level':'HIGH'}
            if category and state!='UNKNOWN':
                validated.update({'matched_identifier':match(json.dumps(data,ensure_ascii=False),tools.trace['resolved_identity']),
                    'evidence_timestamp':unit['evidence_timestamp'],'observation_timestamp':unit['observation_timestamp'],
                    'source_type':unit['source_type'],'exposed_fields':exposed,
                    'identifying_fields_observed':inspected,'subject_reference_present':reference,
                    'condition_facts':conditions,'source_context':unit['record_location'],
                    'confidence_reason':'Ownership and state/category independently parsed from the cited atomic record.'})
                facts.append(validated)
            finish('CONFIRMED','Exact atomic owner or explicit validated relationship path independently verified.',validated_fact=validated)
            continue
        if ftype=='POLICY_CONDITION':
            condition=observation.get('condition_name');expected=observation.get('expected_value')
            if not condition or condition not in conditions:
                finish('UNVERIFIABLE','Requested policy condition is not exposed by the deterministic observation schema.');continue
            actual=conditions[condition]
            if str(actual).lower()!=str(expected).lower():
                finish('REJECTED','Policy condition value differs from the literal observed value.',observed_value=actual);continue
            validated={'case_id':tools.case_id,'system_id':unit['system_id'] or finding['system_id'],'resource_id':rid,
                       'data_category':category,'state':state,'evidence_id':eid,'condition_name':condition,
                       'condition_value':actual,'condition_facts':conditions,'source_type':unit['source_type'],
                       'evidence_timestamp':unit['evidence_timestamp'],'observation_timestamp':unit['observation_timestamp'],
                       'confidence_level':'HIGH','confidence_reason':'Guard verified explicit policy-condition fields.'}
            finish('CONFIRMED','Policy condition matches the deterministic value observed in the atomic record.',validated_fact=validated)
            facts.append(validated);continue
        if not category or state=='UNKNOWN':
            finish('UNVERIFIABLE','Deterministic parser cannot establish both category and state from this record.');continue
        condition_ok=True
        if ftype=='EXPOSED_PII':
            condition_ok=bool(exposed)
        elif ftype=='ACTIVE_DATA_FLOW':
            condition_ok=category=='DATA_FLOW' and state=='ACTIVE'
        elif ftype=='RESTORE_RISK':
            condition_ok=category=='BACKUP_ARCHIVE' and state=='ACTIVE'
        elif ftype=='RESOURCE_STATE':
            condition_ok=True
        if not condition_ok:
            finish('REJECTED','Finding type does not match independently parsed category/state.',observed_category=category,observed_state=state)
            continue
        fact={'case_id':tools.case_id,'system_id':unit['system_id'] or finding['system_id'],'resource_id':rid,
              'data_category':category,'state':state,'matched_identifier':match(json.dumps(data,ensure_ascii=False),tools.trace['resolved_identity']),
              'evidence_id':eid,'evidence_timestamp':unit['evidence_timestamp'],'observation_timestamp':unit['observation_timestamp'],
              'source_type':unit['source_type'],'exposed_fields':exposed,'identifying_fields_observed':inspected,
              'subject_reference_present':reference,'condition_facts':conditions,'source_context':unit['record_location'],
              'confidence_level':'HIGH','confidence_reason':'Independent guard re-derived ownership, state and category from an eligible atomic record.',
              'ownership_provenance':path['kind'],'relationship_path':path['path']}
        facts.append(fact)
        finish('CONFIRMED','Exact ownership and the requested state/exposure/process risk were independently re-derived.',validated_fact=fact)
    return {'results':results,'validated_facts':facts,
            'counts':{s:sum(r['status']==s for r in results) for s in ('CONFIRMED','REJECTED','UNVERIFIABLE')}}

def verify(proposal,tools):
 if not isinstance(proposal,dict):return dict(case_id=tools.case_id,proposal=proposal,status='REJECTED',reason='Proposal is not an object')
 p=proposal;t=tools.trace;rid=p.get('resource_id','');eid=p.get('evidence_id','');action=p.get('action','')
 def result(status,reason,**kw):return dict(case_id=tools.case_id,proposal=p,status=status,reason=reason,**kw)
 if set(p)!={'action','target_step','proposed_step','resource_id','evidence_id','reason','supporting_observation'} or not isinstance(p.get('supporting_observation'),dict):return result('REJECTED','Invalid proposal schema')
 if action not in {'ADD_STEP','REMOVE_LOW_CONFIDENCE_STEP','REPLACE_LOW_CONFIDENCE_STEP','RESOLVE_POLICY_CONDITION','RESOLVE_RESOURCE_OWNERSHIP','RESOLVE_RESOURCE_STATE'}:return result('REJECTED','Unknown proposal action')
 confidence={x['step_no']:x['confidence_level'] for x in t['step_confidence']}
 target=p.get('target_step');proposed=p.get('proposed_step')
 if action in ('REMOVE_LOW_CONFIDENCE_STEP','REPLACE_LOW_CONFIDENCE_STEP'):
  if not isinstance(target,dict) or target not in t['generated_steps']:return result('REJECTED','Target is not an exact existing baseline step')
  if confidence.get(target['step_no'])!='LOW':return result('REJECTED','Only LOW-confidence steps may be removed/replaced')
  if target['resource_id']!=rid:return result('REJECTED','Resource differs from target')
 if proposed:
  if set(proposed)!=STEP_FIELDS or proposed.get('operation') not in OP_STATE or OP_STATE[proposed['operation']]!=proposed.get('state'):return result('REJECTED','Invalid step schema or operation/state pairing')
  if proposed['phase'] not in ('FINDING','REMEDIATION','VERIFICATION') or not isinstance(proposed['step_no'],int):return result('REJECTED','Invalid phase/number')
  if proposed['resource_id']!=rid:return result('REJECTED','Proposed resource differs from claim')
  if action=='ADD_STEP' and any(semantic(proposed)[:5]==semantic(s)[:5] for s in t['generated_steps']):return result('REJECTED','No-op duplicate of a baseline step')
 elif action in ('ADD_STEP','REPLACE_LOW_CONFIDENCE_STEP'):return result('REJECTED','Step patch has no proposed step')
 if eid not in tools.manifest or eid not in tools.allowed or eid not in tools.inspected:return result('REJECTED','Cited file was not eligible, scoped and inspected')
 file=tools.manifest[eid]
 if timestamp(file['captured_at'])>tools.cut:return result('REJECTED','Evidence captured after audit cutoff')
 identity=t['resolved_identity'];extension=Path(file['file_path']).suffix.lower()
 candidates=[]
 if extension in ('.pdf','.png'):
  if action=='RESOLVE_RESOURCE_OWNERSHIP':
   proofs=[r for r in getattr(tools,'binary_verified_ownership',{}).get(eid,[]) if r['resource_id']==rid and available(r,tools.cut) and match(json.dumps(r['data']),identity) and all(r['data'].get(k)==v for k,v in p.get('supporting_observation',{}).get('literal_fields',{}).items())]
   if proofs:return result('CONFIRMED','Two independent passes materially agree on atomic ownership, corroborated by both text layers; no state/category/policy confirmed',verified_ownership=proofs,confirmation_scope='OWNERSHIP_ONLY')
  extracted=getattr(tools,'binary_verified_records',{}).get(eid,[])
  if not extracted:return result('UNVERIFIABLE','Two independent extractions plus text/OCR corroboration not established')
  candidates=extracted
 else:
  candidates=[u for u in tools.data['units'] if u['resource_id']==rid and u['evidence_id']==eid and available(u,tools.cut)]
 if not candidates:return result('UNVERIFIABLE','Resource absent from eligible parsed atomic records; file-level membership/absence extrapolation is not proof')
 facts=[]
 for u in candidates:
  if u['resource_id']!=rid or not available(u,tools.cut):continue
  raw=json.dumps(u['data'],ensure_ascii=False)
  if not exact_contains(raw,rid):continue
  anchored=bool(match(raw,identity));other=set(re.findall(r'\buser_\d+\b',raw))-{identity['user_id']}
  if other:anchored=False
  from src.state import fields
  nested_resources={str(v) for k,v in fields(u['data']) if k=='resource_id'}
  if len(nested_resources)>1:continue
  relation=False
  for edge in t['retrieval'].get('resource_discovery_provenance',{}).get(rid,[]):
   if edge.get('route') in ('evidence_relationship','activity_relationship') and edge.get('from_resource'):
    if any(f['resource_id']==edge['from_resource'] and f.get('confidence_level')=='HIGH' for f in t['facts']):relation=True
  if not anchored and not relation:continue
  asserted=p.get('supporting_observation',{}).get('literal_fields',{})
  if asserted and any(k not in u['data'] or u['data'][k]!=v for k,v in asserted.items()):continue
  if action=='RESOLVE_RESOURCE_OWNERSHIP' and (anchored or relation):
   return result('CONFIRMED','Atomic exact subject/resource relation independently verified; no state/policy conclusion',verified_ownership=[dict(resource_id=rid,evidence_id=eid,record_location=u['record_location'])],confirmation_scope='OWNERSHIP_ONLY')
  category,state,exposed,inspected,reference,conditions=observe(u,identity)
  asserted_state=p.get('supporting_observation',{}).get('state')
  if asserted_state and asserted_state!=state:continue
  if state=='UNKNOWN' or not category:continue
  facts.append(dict(case_id=tools.case_id,system_id=u['system_id'],resource_id=rid,data_category=category,state=state,matched_identifier=match(raw,identity),evidence_id=eid,evidence_timestamp=u['evidence_timestamp'],observation_timestamp=u['observation_timestamp'],source_type=u['source_type'],exposed_fields=exposed,identifying_fields_observed=inspected,subject_reference_present=reference,condition_facts=conditions,source_context=u['record_location'],confidence_level='HIGH',confidence_reason='Guard independently re-derived atomic subject/resource/state and explicit policy fields.'))
 if not facts:return result('UNVERIFIABLE','No atomic exact subject anchor/validated explicit relation with independently parsed category/state')
 # All eligible observations for the same record remain visible; no cherry-picked latest winner.
 states={f['state'] for f in facts};cats={f['data_category'] for f in facts}
 if len(states)!=1 or len(cats)!=1:return result('UNVERIFIABLE','Conflicting eligible atomic observations')
 decisions=apply(facts,compile_rules(tools.data['deletion_rules']),t['request'])
 if len(decisions)!=1:return result('UNVERIFIABLE','System/category ambiguity')
 d=decisions[0]
 if d['unresolved_reason']:return result('UNVERIFIABLE','Policy condition not directly established: '+d['unresolved_reason'])
 expected={('VERIFICATION',VERIFY[d['target_state']])}
 if d['violation']:
  finding,repair=('REPORT_RESTORE_RISK','BLOCK_RESTORE') if d['data_category']=='BACKUP_ARCHIVE' else REPAIR[d['required_action']]
  expected.update({('FINDING',finding),('REMEDIATION',repair)})
 if proposed:
  pair=(proposed['phase'],proposed['operation'])
  if proposed['system_id']!=d['system_id'] or pair not in expected:return result('REJECTED','Proposed system/operation does not follow re-derived state and policy')
  if proposed['phase']=='FINDING' and proposed['evidence_id']!=eid:return result('REJECTED','Finding must cite re-derived supporting file')
  future=proposed['phase']=='REMEDIATION' or proposed['phase']=='VERIFICATION' and (t['final_status']=='INCOMPLETE' or d['violation'])
  if future and proposed['evidence_id']!='':return result('REJECTED','Future work must have an empty citation')
  if not future and proposed['phase']=='VERIFICATION' and proposed['evidence_id']!=eid:return result('REJECTED','Compliant current verification must cite its direct file')
 if action=='REMOVE_LOW_CONFIDENCE_STEP' and (target['phase'],target['operation']) in expected:return result('REJECTED','Existing operation remains supported; removal unjustified')
 return result('CONFIRMED','Atomic ownership, state and literal policy condition independently verified',verified_facts=facts,policy_decision=d,allowed_operation_pairs=sorted(expected))
