"""Fixed development selection and failure-aware, paired evaluation."""
from collections import defaultdict
import hashlib
import math

from .consensus import QuorumPolicy
from .harness import FULL_SYSTEM_HARNESS, AgentSystemVersion
from .types import ExpertVote


def replay_fast_prefix(verdict):
    """Replay the E5 stopping rule on one E4 execution, without new model calls."""
    spec = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E5_GRAPH_FAST)
    executions = verdict['task_executions']
    votes = {vote['expert']: vote for vote in verdict['votes']}
    last = {item['vote']['expert']: index for index, item in enumerate(executions)}
    prefix = spec.expert_order[:spec.early_quorum_after]
    for index in range(len(executions)):
        completed = tuple(expert for expert in spec.expert_order if last.get(expert, math.inf) <= index)
        if completed != prefix:
            continue
        ballots = [ExpertVote(**{key: votes[expert][key] for key in
                     ('expert','label','confidence','validation_status','evidence_ids','rationale')})
                   for expert in prefix]
        fast = QuorumPolicy(quorum=spec.quorum, fast_confidence=spec.fast_confidence).try_fast(ballots)
        if fast is None:
            break
        skipped = executions[index+1:]
        saved_model = sum(item['vote']['model_calls'] for item in skipped)
        saved_tools = sum(item['vote']['tool_calls'] for item in skipped)
        return dict(eligible=True, full_label=verdict['label'], replayed_label=fast.label,
                    label_equivalent=fast.label == verdict['label'],
                    counterfactual_saved_model_calls=saved_model,
                    counterfactual_saved_tool_calls=saved_tools,
                    note='Offline E4-prefix counterfactual; not measured independent E5 latency or cost.')
    return dict(eligible=False, full_label=verdict['label'], replayed_label=verdict['label'],
                label_equivalent=True, counterfactual_saved_model_calls=0,
                counterfactual_saved_tool_calls=0,
                note='No eligible early exit in the observed full-review execution.')


def select_cases(labels, per_stratum=3):
    groups = defaultdict(list)
    for case_id, label in labels.items():
        groups[(label.category, label.vulnerable)].append(case_id)
    selected = []
    for (category, vulnerable), cases in sorted(groups.items()):
        ordered = sorted(cases, key=lambda case: hashlib.sha256(
            f"cv-agent-development-20260919:{case}".encode()).hexdigest())
        if len(ordered) < per_stratum:
            raise ValueError(f"Insufficient cases in {category}/{vulnerable}")
        selected.extend(ordered[:per_stratum])
    return selected


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def provider_usage(events):
    """New journals bind usage to request IDs; preserve historical serial data."""
    tagged = defaultdict(list)
    legacy = []
    for event in events:
        if event.get('request_id'):
            tagged[event['request_id']].append(event)
        else:
            legacy.append(event)
    result = _legacy_provider_usage(legacy)
    conflicts = orphaned = duplicates = 0
    model_ids = set(result['returned_model_ids'])
    for records in tagged.values():
        starts = sum(event['event'] == 'model_start' for event in records)
        if not starts:
            orphaned += any(event['event'] in {'model_response_received', 'model_reply'} for event in records)
            continue
        duplicates += max(0, starts - 1)
        result['requests'] += 1
        result['responses'] += any(event['event'] == 'model_reply' for event in records)
        result['invalid_responses'] += any(event['event'] == 'model_invalid_response' for event in records)
        received = [event.get('summary', {}) for event in records if event['event'] == 'model_response_received']
        payloads = received or [event.get('reply', {}) if event['event'] == 'model_reply' else event.get('summary', {})
                               for event in records if event['event'] in {'model_reply', 'model_invalid_response'}]
        totals = {usage['total_tokens'] for payload in payloads
                  if isinstance((usage := payload.get('usage')), dict)
                  and type(usage.get('total_tokens')) is int and usage['total_tokens'] >= 0}
        if len(totals) == 1:
            result['reported_total_tokens'] += totals.pop()
        else:
            result['requests_without_reported_usage'] += 1
            conflicts += len(totals) > 1
        model_ids.update(event['reply']['model_id'] for event in records if event['event'] == 'model_reply')
    result.update(returned_model_ids=sorted(model_ids), usage_conflicts=conflicts,
                  orphaned_responses=orphaned, duplicate_request_starts=duplicates)
    return result


def _legacy_provider_usage(events):
    replies=[event['reply'] for event in events if event['event']=='model_reply']
    invalid=[event.get('summary',{}) for event in events if event['event']=='model_invalid_response']
    usages=[]
    received = {}
    tagged_requests = any(event['event'] == 'model_start' and event.get('case_id') is not None
                          for event in events)
    for event in events:
        # Each role makes sequential calls, but different trial/role streams
        # can interleave. One global flag double-counted concurrent replies.
        # Legacy single-stream journals sometimes tag only the receive event.
        stream = tuple(event.get(key) for key in ('case_id', 'system', 'role')) if tagged_requests else None
        if event['event'] == 'model_start':
            received[stream] = False
        elif event['event'] == 'model_response_received':
            usages.append(event.get('summary', {}).get('usage'))
            received[stream] = True
        elif event['event'] in {'model_reply', 'model_invalid_response'} and not received.get(stream, False):
            # Historical journals and scripted transports have no receive event.
            payload = event.get('reply', {}) if event['event'] == 'model_reply' else event.get('summary', {})
            usages.append(payload.get('usage'))
    totals=[usage.get('total_tokens') if isinstance(usage,dict) else None for usage in usages]
    known=[value for value in totals if type(value) is int and value>=0]
    requests=sum(event['event']=='model_start' for event in events)
    return dict(requests=requests,responses=len(replies),invalid_responses=len(invalid),
        requests_without_reported_usage=requests-len(known),reported_total_tokens=sum(known),
        returned_model_ids=sorted({reply['model_id'] for reply in replies}),monetary_cost=None,
        note='Token subtotal includes malformed responses with reported usage; unknown usage and pricing are not zero.')


def wilson(success, total):
    """Descriptive binomial interval, not a repository-generalization interval."""
    if not total:
        return None
    z = 1.959963984540054
    p = success / total
    denominator = 1 + z*z/total
    center = (p + z*z/(2*total))/denominator
    radius = z * math.sqrt(p*(1-p)/total + z*z/(4*total*total))/denominator
    return [max(0, center-radius), min(1, center+radius)]


def metrics(rows):
    counts = dict(tp=0, fp=0, tn=0, fn=0, abstained=0, failed=0,
                  interrupted=0, not_run=0)
    for row in rows:
        if row['status'] != 'completed':
            counts[row['status']] += 1
        else:
            actual = row['ground_truth'] == 'VULNERABLE'
            predicted = row['predicted_label'] == 'VULNERABLE'
            counts['tp' if actual and predicted else 'fn' if actual else
                   'fp' if predicted else 'tn'] += 1
    total = len(rows)
    positives = sum(row['ground_truth'] == 'VULNERABLE' for row in rows)
    negatives = total - positives
    tp, fp, tn, fn = (counts[name] for name in ('tp', 'fp', 'tn', 'fn'))
    evidence_counts = dict(CONFIRMED=0, REFUTED=0, UNRESOLVED=0)
    supported_material = unsupported_material = 0
    for row in rows:
        votes = (row.get('verdict') or {}).get('votes', [])
        for vote in votes:
            evidence_counts[vote['validation_status']] += 1
        if row['status'] == 'completed':
            expected = 'CONFIRMED' if row['predicted_label'] == 'VULNERABLE' else 'REFUTED'
            if any(vote['validation_status'] == expected and
                   vote['label'] == row['predicted_label'] for vote in votes):
                supported_material += 1
            else:
                unsupported_material += 1
    return {
        **counts, 'total': total, 'positives': positives, 'negatives': negatives,
        'provisional': bool(counts['not_run'] or counts['interrupted']),
        'coverage': ratio(tp+fp+tn+fn, total), 'strict_recall': ratio(tp, positives),
        'covered_recall': ratio(tp, tp+fn), 'precision': ratio(tp, tp+fp),
        'population_fpr': ratio(fp, negatives), 'covered_fpr': ratio(fp, fp+tn),
        'conservative_fpr': ratio(negatives-tn, negatives),
        'accuracy': ratio(tp+tn, total),
        'strict_recall_wilson95': (wilson(tp, positives) if not counts['not_run'] and not counts['interrupted'] else None),
        'population_fpr_wilson95': (wilson(fp, negatives) if not counts['not_run'] and not counts['interrupted'] else None),
        'model_requests': sum(row['model_calls'] for row in rows),
        'tool_calls': sum(row['tool_calls'] for row in rows),
        'elapsed_seconds': sum(row['latency_sec'] for row in rows),
        'vote_validation_status_counts': evidence_counts,
        'material_with_matching_validator_vote': supported_material,
        'material_without_matching_validator_vote': unsupported_material,
        'validation_note': 'A typed validator vote is not necessarily a dynamic exploit reproduction.',
    }


def paired(rows, left, right):
    groups = defaultdict(dict)
    for row in rows:
        groups[row['case_id']][row['system']] = row
    result = dict(left_wins=0, right_wins=0, ties=0, unavailable=0,
                  completed_label_disagreements=0)
    for pair in groups.values():
        if left not in pair or right not in pair:
            result['unavailable'] += 1
            continue
        a, b = pair[left], pair[right]
        if a['status'] in {'failed', 'interrupted', 'not_run'} or b['status'] in {
                'failed', 'interrupted', 'not_run'}:
            result['unavailable'] += 1
            continue
        ca = a['predicted_label'] == a['ground_truth']
        cb = b['predicted_label'] == b['ground_truth']
        result['ties' if ca == cb else 'left_wins' if ca else 'right_wins'] += 1
        result['completed_label_disagreements'] += a['predicted_label'] != b['predicted_label']
    return result
