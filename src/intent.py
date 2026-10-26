"""Authorization gate extracted without semantic changes."""
import re
from src.request_intent import analyze

def intent(request, manual_labels):
    manual = manual_labels.get(request['case_id'])
    if manual == 'NOT_DELETION':
        return {'applicable': False, 'reason': 'Explicit human label', 'manual_label': manual}
    signals = analyze(request['request_text'])
    if signals['injection_suspicion'] or signals['conflicting_signal']:
        return {'applicable': None, 'reason': 'Conflicting/injection-suspicious wording', 'signals': signals}
    if signals['deletion_signal'] or signals['verification_signal']:
        return {'applicable': True, 'reason': 'Recognized explicit deletion or deletion-verification request', 'signals': signals}
    if re.search('\\b(?:delete|erase|remove)\\b[^.!?]{0,60}\\b(?:export file|search result|records under|my name|contact details)\\b', request['request_text'], re.I):
        return {'applicable': True, 'reason': 'Explicit removal of direct personal identifiers', 'signals': signals}
    if re.search('delet', request['request_text'], re.I) and re.search('\\b(?:investigate|finish|complete)\\b[^.!?]{0,50}\\bdeletion\\b', request['request_text'], re.I):
        return {'applicable': True, 'reason': 'Explicit request to investigate/finish deletion', 'signals': signals}
    if re.search('delet', request['request_text'], re.I) and (re.search('\\b(?:check|verify|confirm)\\b[^.!?]{0,100}\\bnothing\\b[^.!?]{0,100}\\bleft behind\\b', request['request_text'], re.I) or re.search('\\bdisable\\b[^.!?]{0,50}\\bsynchronization\\b', request['request_text'], re.I)):
        return {'applicable': True, 'reason': 'Explicit post-deletion residual-data verification/flow request', 'signals': signals}
    return {'applicable': None, 'reason': 'Unrecognized intent; requires manual review', 'signals': signals}
