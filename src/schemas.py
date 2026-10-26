"""Shared data fields and challenge operation order; no benchmark labels."""
from dataclasses import dataclass, field
from datetime import datetime

PHASES = ['FINDING', 'REMEDIATION', 'VERIFICATION']
OPERATIONS = [
    'REPORT_REMAINING_RECORD', 'REPORT_EXPOSED_PII', 'REPORT_ACTIVE_DATA_FLOW', 'REPORT_RESTORE_RISK',
    'DISABLE_DATA_FLOW', 'BLOCK_RESTORE', 'DELETE_RECORD', 'REDACT_RECORD', 'ANONYMIZE_RECORD',
    'VERIFY_RECORD_ABSENT', 'VERIFY_RECORD_PRESENT', 'VERIFY_RECORD_REDACTED', 'VERIFY_RECORD_ANONYMIZED',
    'VERIFY_DATA_FLOW_DISABLED', 'VERIFY_RESTORE_BLOCKED',
]
OP_STATE = dict(zip(OPERATIONS, [
    'PRESENT', 'PRESENT', 'ACTIVE', 'ACTIVE', 'DISABLED', 'BLOCKED', 'ABSENT', 'REDACTED', 'ANONYMIZED',
    'ABSENT', 'PRESENT', 'REDACTED', 'ANONYMIZED', 'DISABLED', 'BLOCKED',
]))


def timestamp(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def step_key(step):
    return PHASES.index(step['phase']), OPERATIONS.index(step['operation']), step['system_id'], step['resource_id']


@dataclass
class Fact:
    case_id: str
    system_id: str
    resource_id: str
    data_category: str
    state: str
    matched_identifier: str
    evidence_id: str
    evidence_timestamp: str
    source_type: str
    observation_timestamp: str = ''
    exposed_fields: list = field(default_factory=list)
    identifying_fields_observed: bool = False
    subject_reference_present: bool = False
    condition_facts: dict = field(default_factory=dict)
    source_context: str = ''
