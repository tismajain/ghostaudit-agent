"""Exact identifier ownership and complete identity lineage; no fuzzy merging."""
import re
from collections import defaultdict

FIELDS = ('user_id', 'name', 'email', 'phone', 'email_hash')


def normalize(value):
    return str(value).strip().casefold()


def exact_contains(text, value):
    if not value:
        return False
    return bool(re.search(r'(?<![\w@.+-])' + re.escape(normalize(value)) + r'(?![\w@.+-])', normalize(text)))


def ownership(identities, history):
    owners = defaultdict(set)
    intervals = []
    for user in identities:
        uid = user['user_id']
        for field in FIELDS:
            events = sorted((h for h in history if h['user_id'] == uid and h['field_name'] == field), key=lambda h: h['event_time'])
            if events:
                value, start = events[0]['old_value'], None
                for event in events:
                    intervals.append(dict(user_id=uid, field=field, value=value, start=start, end=event['event_time']))
                    value, start = event['new_value'], event['event_time']
                intervals.append(dict(user_id=uid, field=field, value=value, start=start, end=None))
            else:
                intervals.append(dict(user_id=uid, field=field, value=user[field], start=None, end=None))
            if user[field]:
                owners[normalize(user[field])].add(uid)
    for interval in intervals:
        if interval['value']:
            owners[normalize(interval['value'])].add(interval['user_id'])
    return owners, intervals


def resolve(request, identities, history):
    owners, intervals = ownership(identities, history)
    email = normalize(request['email'])
    candidates = {u['user_id'] for u in identities if normalize(u['email']) == email}
    candidates.update(h['user_id'] for h in history if h['field_name'] == 'email' and email in
                      (normalize(h['old_value']), normalize(h['new_value'])))
    result = dict(user_id=None, current_identifiers={}, historical_identifiers={}, search_identifiers=[],
                  identity_source_rows=[], ownership_intervals=[], collisions=[], conflicts=[])
    if len(candidates) != 1:
        result['conflicts'].append(dict(type='REQUEST_IDENTITY_UNRESOLVED', candidate_user_ids=sorted(candidates)))
        return result
    uid = next(iter(candidates))
    user = next(u for u in identities if u['user_id'] == uid)
    events = [h for h in history if h['user_id'] == uid]
    historical = defaultdict(set)
    for event in events:
        historical[event['field_name']].update((event['old_value'], event['new_value']))
    search = {user[field] for field in FIELDS if user[field]}
    search.update(v for values in historical.values() for v in values if v)
    for value in sorted(search):
        if len(owners[normalize(value)]) > 1:
            relevant = [i for i in intervals if normalize(i['value']) == normalize(value)]
            overlap = []
            for i, a in enumerate(relevant):
                for b in relevant[i+1:]:
                    if a['user_id'] == b['user_id']:
                        continue
                    if (not a['end'] or not b['start'] or b['start'] < a['end']) and (not b['end'] or not a['start'] or a['start'] < b['end']):
                        overlap.append([a['user_id'], b['user_id']])
            result['collisions'].append(dict(identifier=value, owners=sorted(owners[normalize(value)]),
                                              overlapping_owners=overlap, ownership_intervals=relevant))
    result.update(user_id=uid, current_identifiers={k: user[k] for k in FIELDS},
                  historical_identifiers={k: sorted(v - {user.get(k, '')}) for k, v in historical.items()},
                  search_identifiers=sorted(search), identity_source_rows=[{'source': 'user_identities', **user}] +
                  [{'source': 'user_audit_log', **event} for event in events],
                  ownership_intervals=[i for i in intervals if i['user_id'] == uid])
    # Even disjoint ownership intervals flag email reuse; intervals never discard history.
    if any(normalize(c['identifier']) == email for c in result['collisions']):
        result['conflicts'].append(dict(type='REQUEST_EMAIL_COLLISION', owners=sorted(owners[email])))
    return result


def match(text, identity):
    # Names are retained for debugging/search context but are not sufficient identity proof.
    names = {normalize(identity['current_identifiers'].get('name', ''))}
    names.update(normalize(v) for v in identity['historical_identifiers'].get('name', []))
    collided = {normalize(c['identifier']) for c in identity['collisions']}
    matches = [v for v in identity['search_identifiers'] if normalize(v) not in names | collided and exact_contains(text, v)]
    return sorted(matches, key=lambda v: (v != identity['user_id'], v))[0] if matches else ''
