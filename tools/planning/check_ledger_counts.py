#!/usr/bin/env python3
"""Enforce TODO header == checkboxes == traceability counts (LEDGER-RECONCILE01).

Census sources: TODO.md header ("Fifty-one of 86 tasks accepted", "120
requirements and 86 tasks", "179 source-obligation mappings"), task-ID
checkboxes ("- [x] [SB01: ..."), and the traceability registry (tasks,
requirements, source_obligations, counts block). Any single-count edit in
any one source must fail; agreement across all three exits 0.

Usage:
    python3 tools/planning/check_ledger_counts.py [--todo PATH]
        [--registry PATH] [--repo-root PATH]
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

ONES = {'zero': 0, 'one': 1, 'two': 2, 'three': 3, 'four': 4, 'five': 5,
        'six': 6, 'seven': 7, 'eight': 8, 'nine': 9, 'ten': 10,
        'eleven': 11, 'twelve': 12, 'thirteen': 13, 'fourteen': 14,
        'fifteen': 15, 'sixteen': 16, 'seventeen': 17, 'eighteen': 18,
        'nineteen': 19}
TENS = {'twenty': 20, 'thirty': 30, 'forty': 40, 'fifty': 50,
        'sixty': 60, 'seventy': 70, 'eighty': 80, 'ninety': 90}


def number_word(text):
    """English 0-99 (case-insensitive, hyphen or space separated) to int."""
    parts = text.lower().replace('-', ' ').split()
    if len(parts) == 1 and parts[0] in ONES:
        return ONES[parts[0]]
    if len(parts) == 1 and parts[0] in TENS:
        return TENS[parts[0]]
    if len(parts) == 2 and parts[0] in TENS and parts[1] in ONES:
        return TENS[parts[0]] + ONES[parts[1]]
    raise ValueError(f'not a 0-99 number word: {text!r}')


HEADER_ACCEPTED = re.compile(
    r'\*\*([A-Za-z-]+(?: [A-Za-z-]+)?) of (\d+) tasks accepted\*\*')
HEADER_TOTALS = re.compile(r'\*\*(\d+) requirements and (\d+) tasks\*\*')
HEADER_OBLIGATIONS = re.compile(r'(\d+)\s+source-obligation mappings')
TASK_BOX = re.compile(r'^- \[(x| )\] \[([A-Z0-9]+):')


def census_todo(path):
    """Return (header_dict, checked_ids, unchecked_ids, errors)."""
    errors = []
    try:
        text = path.read_text(encoding='utf-8')
    except OSError as exc:
        return {}, set(), set(), [{'code': 'TODO_UNREADABLE',
                                   'context': f'{path}: {exc}'}]
    header = {}
    match = HEADER_ACCEPTED.search(text)
    if not match:
        errors.append({'code': 'HEADER_ACCEPTED_MISSING',
                       'context': 'no "**<words> of <N> tasks accepted**" line'})
    else:
        try:
            header['accepted'] = number_word(match.group(1))
        except ValueError:
            errors.append({'code': 'HEADER_ACCEPTED_UNPARSEABLE',
                           'context': match.group(1)})
        header['tasks_total'] = int(match.group(2))
    match = HEADER_TOTALS.search(text)
    if not match:
        errors.append({'code': 'HEADER_TOTALS_MISSING',
                       'context': 'no "**<N> requirements and <M> tasks**" line'})
    else:
        header['requirements'] = int(match.group(1))
        header['tasks_total_2'] = int(match.group(2))
    match = HEADER_OBLIGATIONS.search(text)
    if not match:
        errors.append({'code': 'HEADER_OBLIGATIONS_MISSING',
                       'context': 'no "<N> source-obligation mappings" line'})
    else:
        header['obligations'] = int(match.group(1))
    checked, unchecked = set(), set()
    for lineno, line in enumerate(text.splitlines(), 1):
        box = TASK_BOX.match(line)
        if not box:
            continue
        if box.group(2) in checked or box.group(2) in unchecked:
            errors.append({'code': 'CHECKBOX_DUPLICATE_ID',
                           'context': f'{box.group(2)} at line {lineno}'})
        if box.group(1) == 'x':
            checked.add(box.group(2))
        else:
            unchecked.add(box.group(2))
    return header, checked, unchecked, errors


def census_registry(path):
    """Return (census_dict, errors)."""
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        return {}, [{'code': 'REGISTRY_UNREADABLE',
                     'context': f'{path}: {exc}'}]
    errors = []
    census = {}
    tasks = data.get('tasks')
    if not isinstance(tasks, list):
        errors.append({'code': 'REGISTRY_TASKS_SHAPE',
                       'context': 'tasks is not a list'})
        return census, errors
    accepted, planned, seen = set(), set(), set()
    for entry in tasks:
        if not isinstance(entry, dict) or 'id' not in entry:
            errors.append({'code': 'REGISTRY_TASK_SHAPE',
                           'context': 'task entry without id'})
            continue
        if entry['id'] in seen:
            errors.append({'code': 'REGISTRY_DUPLICATE_ID',
                           'context': entry['id']})
        seen.add(entry['id'])
        if entry.get('status') == 'ACCEPTED':
            accepted.add(entry['id'])
        elif entry.get('status') == 'PLANNED':
            planned.add(entry['id'])
        else:
            errors.append({'code': 'REGISTRY_UNKNOWN_STATUS',
                           'context': f"{entry['id']}: {entry.get('status')!r}"})
    census['tasks_total'] = len(tasks)
    census['accepted_ids'] = accepted
    census['planned_ids'] = planned
    counts = data.get('counts', {})
    census['counts_tasks'] = counts.get('tasks')
    census['counts_requirements'] = counts.get('requirements')
    census['requirements_total'] = len(data['requirements']) \
        if isinstance(data.get('requirements'), list) else None
    obligations = data.get('source_obligations')
    census['obligations_total'] = len(obligations) \
        if isinstance(obligations, (list, dict)) else None
    if census['requirements_total'] is None:
        errors.append({'code': 'REGISTRY_REQUIREMENTS_SHAPE',
                       'context': 'requirements is not a list'})
    if census['obligations_total'] is None:
        errors.append({'code': 'REGISTRY_OBLIGATIONS_SHAPE',
                       'context': 'source_obligations is not a list/dict'})
    return census, errors


def check(header, checked, unchecked, census):
    """Cross-source agreement; returns a list of error dicts."""
    errors = []
    box_total = len(checked) + len(unchecked)
    pairs = [
        ('HEADER_BOX_ACCEPTED', header.get('accepted'), len(checked),
         'header accepted vs checked boxes'),
        ('HEADER_REGISTRY_ACCEPTED', header.get('accepted'),
         len(census.get('accepted_ids', set())),
         'header accepted vs registry ACCEPTED'),
        ('HEADER_TASKS_TOTAL', header.get('tasks_total'),
         header.get('tasks_total_2'),
         'header accepted-line total vs totals line'),
        ('HEADER_BOX_TOTAL', header.get('tasks_total'), box_total,
         'header tasks total vs checkbox total'),
        ('HEADER_REGISTRY_TASKS', header.get('tasks_total'),
         census.get('tasks_total'), 'header tasks total vs registry tasks'),
        ('HEADER_COUNTS_TASKS', header.get('tasks_total'),
         census.get('counts_tasks'), 'header tasks total vs counts.tasks'),
        ('HEADER_REQUIREMENTS', header.get('requirements'),
         census.get('requirements_total'),
         'header requirements vs registry requirements'),
        ('HEADER_COUNTS_REQUIREMENTS', header.get('requirements'),
         census.get('counts_requirements'),
         'header requirements vs counts.requirements'),
        ('HEADER_OBLIGATIONS', header.get('obligations'),
         census.get('obligations_total'),
         'header obligations vs registry source_obligations'),
        ('BOX_PLANNED', len(unchecked), len(census.get('planned_ids', set())),
         'unchecked boxes vs registry PLANNED'),
    ]
    for code, left, right, context in pairs:
        if left is None or right is None:
            errors.append({'code': 'CENSUS_VALUE_MISSING',
                           'context': context})
        elif left != right:
            errors.append({'code': code,
                           'context': f'{context}: {left} != {right}'})
    registry_accepted = census.get('accepted_ids', set())
    if checked != registry_accepted:
        errors.append({'code': 'ACCEPTED_ID_SET',
                       'context': 'checked box ids != registry ACCEPTED ids: '
                       f'only-box={sorted(checked - registry_accepted)} '
                       f'only-registry={sorted(registry_accepted - checked)}'})
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--todo', type=Path, default=ROOT / 'TODO.md')
    parser.add_argument('--registry', type=Path,
                        default=ROOT / 'docs/superpowers/plans/2026-10-17-scopebase-traceability.json')
    parser.add_argument('--repo-root', type=Path, default=ROOT)
    args = parser.parse_args(argv)
    report = {'status': 'DISAGREE', 'census': {}, 'errors': []}
    header, checked, unchecked, errors = census_todo(args.todo)
    report['errors'].extend(errors)
    census, errors = census_registry(args.registry)
    report['errors'].extend(errors)
    if not report['errors']:
        report['errors'].extend(check(header, checked, unchecked, census))
    report['census'] = {
        'header': header,
        'checked_boxes': len(checked),
        'unchecked_boxes': len(unchecked),
        'registry_tasks': census.get('tasks_total'),
        'registry_accepted': len(census.get('accepted_ids', set())),
        'registry_planned': len(census.get('planned_ids', set())),
        'registry_requirements': census.get('requirements_total'),
        'registry_obligations': census.get('obligations_total'),
    }
    if not report['errors']:
        report['status'] = 'AGREE'
    json.dump(report, sys.stdout, indent=1)
    sys.stdout.write('\n')
    return 0 if report['status'] == 'AGREE' else 1


if __name__ == '__main__':
    sys.exit(main())
