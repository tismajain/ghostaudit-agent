"""Text-only request-intent heuristics; unchanged from the measured engine."""
import csv
import hashlib
import re
import statistics
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
ALLOWED_LABELS = {'DELETE', 'VERIFY_DELETION', 'NOT_DELETION', 'AMBIGUOUS'}
LANGUAGES = {'Portuguese': '\\b(exclusao|conta|verifiquem|solicitacao)\\b', 'Spanish': '\\b(cuenta|eliminacion|correo|pueden)\\b', 'French': '\\b(compte|suppression|veuillez|je|supprimer)\\b', 'German': '\\b(konto|loschen|loschung|bitte|meine)\\b', 'English': '\\b(please|account|my|the|i|you|me|data|information)\\b'}
NEGATIONS = ["\\b(?:do not|don't|never|must not|not to|without)\\s+(?:permanently\\s+)?(?:delete|erase|remove|close|removing)\\b[^.!?]*", '\\bnot\\s+(?:a\\s+)?(?:request(?:ing)?|asking)\\s+(?:for\\s+|to\\s+)?(?:deletion|erasure|delete|erase)\\b[^.!?]*', '\\b(?:no quiero|no solicito)\\s+(?:eliminar|borrar)\\b[^.!?]*', '\\b(?:ne supprimez pas|nicht loschen)\\b[^.!?]*']
DELETION = {'direct_delete_erase': '\\b(?:delete|erase)\\b[^.!?]{0,70}\\b(?:account|profile|data|information|records|details)\\b', 'request_deletion': '\\b(?:request|requesting|request for|submit a request|begin|process)\\b[^.!?]{0,80}\\b(?:deletion|erasure|delete|erase)\\b', 'remove_subject_data': '\\bremove\\b[^.!?]{0,50}\\b(?:account|profile|personal information|personal details|personal data)\\b', 'desired_permanent_removal': '\\b(?:would like|want|asking|need)\\b[^.!?]{0,100}\\b(?:deleted|erased|removed|closed permanently|permanently closed)\\b', 'permanent_closure': '\\b(?:close|closing)\\b[^.!?]{0,40}\\baccount\\b[^.!?]{0,30}\\bpermanently\\b', 'spanish_deletion': '\\b(?:eliminacion|eliminar|borrar)\\b[^.!?]*\\bcuenta\\b', 'french_deletion': '\\b(?:suppression|supprimer|effacer)\\b[^.!?]*\\bcompte\\b', 'portuguese_deletion': '\\b(?:exclusao|excluir|apagar)\\b[^.!?]*\\bconta\\b', 'german_deletion': '\\b(?:loschen|loschung)\\b[^.!?]*\\bkonto\\b|\\bkonto\\b[^.!?]*\\b(?:loschen|loschung)\\b', 'japanese_deletion': '(?:アカウント|個人情報).{0,50}削除|削除.{0,50}(?:アカウント|個人情報)', 'korean_deletion': '(?:계정|개인정보).{0,50}삭제|삭제.{0,50}(?:계정|개인정보)'}
VERIFY = {'verify_completed_deletion': '\\b(?:verify|check|confirm|tell me)\\b[^.!?]{0,100}\\b(?:whether|that|if)\\b[^.!?]{0,80}\\b(?:deleted|removed|erased|gone|deletion (?:occurred|completed|was complete|is complete))\\b', 'past_deletion_question': '\\b(?:was|has|is)\\s+my\\s+(?:account|data|profile)\\b[^.!?]{0,25}\\b(?:deleted|removed|erased|gone)\\b', 'audit_completed_deletion': '\\b(?:audit|verify|check)\\b[^.!?]{0,50}\\b(?:deletion|data is gone|account is gone)\\b'}
NON_DELETION = {'access_or_copy': '\\b(?:access (?:to )?my data|(?:give|send|export|download)\\b[^.!?]{0,50}\\b(?:copy|account information|my data)|(?:need|want|like)\\b[^.!?]{0,20}\\ba copy|what (?:personal )?information (?:do )?you (?:hold|have)|information you hold)\\b', 'portability': '\\b(?:portability|portable format)\\b', 'correction_update': '\\b(?:correct|update|change|replace)\\b[^.!?]{0,65}\\b(?:email|address|number|phone|surname|name|information|profile|details|it)\\b|\\b(?:surname|name)\\b[^.!?]{0,30}\\bmisspelled\\b', 'marketing_opt_out': '\\b(?:unsubscribe|opt[ -]out|stop\\b[^.!?]{0,30}\\bemails|marketing lists|promotional emails)\\b', 'keep_account': '\\b(?:keep\\b[^.!?]{0,25}\\baccount|leave\\b[^.!?]{0,60}\\b(?:active|in place)|continue using|still (?:use|need|want)\\b[^.!?]{0,35}\\b(?:account|receipts|service messages))\\b', 'account_help': '\\b(?:reset(?:ting)? (?:the |my )?login|cant access my profile|help (?:with|accessing|resetting)\\b[^.!?]{0,30}\\b(?:login|account))\\b', 'objection': '\\b(?:object to|objection to|restrict processing)\\b'}
INJECTION = {'instruction_override': '\\b(?:ignore|override|disregard)\\b[^.!?]{0,50}\\b(?:instructions|rules|prompt|policy)\\b', 'role_or_prompt_reference': '\\b(?:system prompt|developer message|assistant:|you are (?:now|chatgpt)|jailbreak)\\b|<\\|(?:im_start|system|assistant)', 'force_output': '\\b(?:output|return|respond with|classify (?:this|me) as)\\b[^.!?]{0,40}\\b(?:complete|incomplete|not_applicable|json|delete|not_deletion)\\b'}

def normalized(text):
    text = text.casefold().replace('’', "'")
    return unicodedata.normalize('NFC', ''.join((c for c in unicodedata.normalize('NFKD', text) if not unicodedata.combining(c))))

def hits(patterns, text):
    return [name for name, pattern in patterns.items() if re.search(pattern, text, re.I)]

def language(text):
    if re.search('[\\u3040-\\u30ff]', text):
        return 'Japanese'
    if re.search('[\\uac00-\\ud7af]', text):
        return 'Korean'
    if re.search('[\\u4e00-\\u9fff]', text):
        return 'CJK_undetermined'
    scores = {name: len(re.findall(pattern, normalized(text))) for name, pattern in LANGUAGES.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] else 'undetermined'

def analyze(text, median_length=200, mad=20):
    t = normalized(text)
    negative = []
    positive = t
    for pattern in NEGATIONS:
        negative.extend((m.group() for m in re.finditer(pattern, t)))
        positive = re.sub(pattern, ' ', positive)
    deletion = hits(DELETION, positive)
    verification = hits(VERIFY, positive)
    nondeletion = hits(NON_DELETION, t)
    injection = hits(INJECTION, t)
    if negative:
        nondeletion.append('explicit_do_not_delete_or_equivalent')
    lexical_deletion = bool(re.search('\\b(?:delet\\w*|eras\\w*|remov\\w*)\\b', positive))
    lang = language(text)
    multilingual = lang != 'English'
    unusual = not text.strip() or len(text) < 40 or len(text) > max(400, median_length + 8 * max(mad, 1)) or bool(re.search('[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f]|(.)\\1{7,}', text))
    conflict = bool(deletion and nondeletion)
    unresolved = not deletion and (not verification) and (not nondeletion)
    if injection:
        group = 'injection_suspicious'
    elif conflict:
        group = 'conflicting_ambiguous'
    elif nondeletion:
        group = 'possible_non_deletion'
    elif verification and (not deletion):
        group = 'verification_only'
    elif deletion:
        group = 'deletion_oriented'
    else:
        group = 'ambiguous_low_confidence'
    review = bool(nondeletion or conflict or injection or multilingual or unusual or unresolved)
    proposed = 'AMBIGUOUS' if conflict or injection or unresolved else 'NOT_DELETION' if nondeletion else 'VERIFY_DELETION' if verification and (not deletion) else 'DELETE'
    notes = {'proposal_not_ground_truth': True, 'positive_deletion_matches': deletion, 'verification_matches': verification, 'non_deletion_matches': nondeletion, 'explicit_do_not_delete': bool(negative), 'negated_clauses': negative, 'injection_matches': injection, 'unusual_wording': unusual, 'multilingual_or_low_confidence': multilingual or unresolved or unusual, 'lexical_deletion_mention_without_positive_request': lexical_deletion and (not deletion), 'language_method': 'Unicode script plus small word lexicon; heuristic, not validated', 'review_reason': (['non-deletion action or prohibition'] if nondeletion else []) + (['mixed positive deletion and non-deletion signals'] if conflict else []) + (['possible instruction injection'] if injection else []) + (['multilingual/undetermined language'] if multilingual else []) + (['unusual text shape/length'] if unusual else []) + (['no recognized intent pattern'] if unresolved else [])}
    return dict(candidate_group=group, deletion_signal=bool(deletion), verification_signal=bool(verification), non_deletion_signal=bool(nondeletion), conflicting_signal=conflict, injection_suspicion=bool(injection), language_estimate=lang, needs_manual_review=review, notes=notes, proposed_label=proposed)
