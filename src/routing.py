"""Case-scoped final routing; discovery is never ownership/state proof."""
import json,re
from pathlib import Path
from src.identity import normalize
from src.ingest import explicit_resource_links
from src.schemas import timestamp
from src.request_intent import analyze

class EvidenceScope:
 def __init__(self,root,data,cache):
  self.data=data;self.manifest={r['file_id']:r for r in data['evidence_files']};self.cache=cache
  self.raw={eid:json.dumps({'records':c.get('records',[]),'text':c.get('text','')},ensure_ascii=False).casefold() for eid,c in cache.items()}
  self.edges=[]
  for u in data['units']:
   at=max(timestamp(u['evidence_timestamp']),timestamp(u['observation_timestamp']))
   for e in explicit_resource_links(u['data'],u.get('text',''),u.get('resource_id','')):self.edges.append((at,e['source'],e['target']))
  for a in data['system_activity']:
   for e in explicit_resource_links(a,a.get('details',''),a.get('resource_id','')):self.edges.append((timestamp(a['event_time']),e['source'],e['target']))
 def for_case(self,request,identity,facts=()):
  if not identity.get('user_id') or identity.get('conflicts'):return []
  cut=timestamp(request['audit_at'])
  names={normalize(identity.get('current_identifiers',{}).get('name',''))}
  names.update(normalize(x) for x in identity.get('historical_identifiers',{}).get('name',[]))
  collided={normalize(x['identifier']) for x in identity.get('collisions',[])}
  terms={normalize(x) for x in identity.get('search_identifiers',[]) if x and normalize(x) not in names|collided}
  if not terms:return []
  pattern=re.compile(r'(?<![\w@.+-])(?:'+'|'.join(re.escape(x) for x in sorted(terms))+r')(?![\w@.+-])')
  eligible={eid for eid,m in self.manifest.items() if timestamp(m['captured_at'])<=cut}
  direct={eid for eid in eligible if pattern.search(self.raw.get(eid,''))}
  anchors={f['resource_id'] for f in facts if f.get('confidence_level')=='HIGH'}
  for eid in direct:
   for r in self.cache[eid].get('records',[]):
    if r.get('resource_id') and pattern.search(json.dumps(r.get('data',{}),ensure_ascii=False).casefold()):anchors.add(r['resource_id'])
  reachable=set(anchors)
  for _ in range(3):
   for at,a,b in self.edges:
    if at<=cut and (a in reachable or b in reachable):reachable.update((a,b))
  # Explicit graph targets are discovery candidates; guard still re-derives atomic ownership.
  for eid in eligible:
   if any(r.get('resource_id') in reachable for r in self.cache[eid].get('records',[])):direct.add(eid)
   if Path(self.manifest[eid]['file_path']).suffix.lower() in {'.pdf','.png'} and any(re.search(r'(?<!\w)'+re.escape(rid)+r'(?!\w)',self.cache[eid].get('text','')) for rid in reachable):direct.add(eid)
  return sorted(direct)

def route(trace,scoped_ids,manifest,multilingual=None):
 binary=sorted(e for e in scoped_ids if Path(manifest.get(e,{}).get('file_path','')).suffix.lower() in {'.pdf','.png'})
 if multilingual is None:multilingual=bool(analyze(trace['request']['request_text'])['notes']['multilingual_or_low_confidence'])
 reasons=[]
 if any(x.get('confidence_level')=='LOW' for x in trace.get('step_confidence',[])):reasons.append('LOW_CONFIDENCE_STEP')
 if trace.get('retrieval',{}).get('linked_resources_without_state'):reasons.append('UNRESOLVED_RESOURCES')
 if binary:reasons.append('PDF_PNG_EVIDENCE')
 if multilingual:reasons.append('MULTILINGUAL_LOW_CONFIDENCE')
 priority='P1' if any(x in reasons for x in ('LOW_CONFIDENCE_STEP','UNRESOLVED_RESOURCES')) else 'P2' if binary else 'P3' if multilingual else ''
 return {'routed':bool(reasons),'reasons':reasons,'priority':priority,'scoped_pdf_png_evidence_ids':binary,'candidate_evidence_ids':scoped_ids}
