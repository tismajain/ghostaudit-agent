"""Screened, abstaining account workflow attribution. Never establishes state."""
from datetime import timedelta
from src.schemas import timestamp


def account_workflow_candidate(request, activities):
    center = timestamp(request['reported_at'])
    lower = center - timedelta(hours=2)
    upper = min(center + timedelta(hours=2), timestamp(request['audit_at']))
    events = [dict(event) for event in activities
              if event['source_system'] == 'deletion_worker'
              and event['target_system'] == 'account_service'
              and event['event_type'] == 'DELETE_RECORD'
              and event['resource_id'].startswith('account_')
              and lower <= timestamp(event['event_time']) <= upper]
    events.sort(key=lambda event: (event['event_time'], event['activity_id']))
    resources = sorted({event['resource_id'] for event in events})
    return dict(rule_id='UNIQUE_REPORTED_2h', family='account', provenance_type='TEMPORAL_WORKFLOW',
                anchor_time=request['reported_at'], window_seconds_each_side=7200,
                window_start=lower.isoformat(), window_end=upper.isoformat(), audit_at=request['audit_at'],
                selected_resource_id=resources[0] if len(resources) == 1 else None,
                candidate_resource_ids=resources, events=events,
                decision='UNIQUE_CANDIDATE' if len(resources) == 1 else 'ABSTAIN_MULTIPLE' if resources else 'ABSTAIN_EMPTY',
                confidence='LOWER_THAN_EXACT_IDENTITY', is_identity_proof=False, reported_result_used_as_proof=False)
