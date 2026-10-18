#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded local SB03 documentation checks; never evaluates qualification.

Exit 0: structurally valid; 3: invalid content/IO/bounds; 64: usage.
No subprocess, Git, network, code execution or runtime-support inputs.
"""
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import sys
from urllib.parse import unquote, urlsplit

# Support both script execution and import without importing a script with effects.
try:
    from .check_traceability import unique_members, document_link
except ImportError:
    from check_traceability import unique_members, document_link

ROOT = Path(__file__).resolve().parents[2]
JSON_LIMIT = 1024 * 1024
DOCUMENT_LIMIT = 2 * 1024 * 1024
RECORD_LIMIT = 256
DOCUMENT_LIMIT_COUNT = 256
ISSUE_LIMIT = 256
DIAGNOSTIC_LIMIT = 128
REGISTRY = 'profiles/schema-versions.json'
TRACEABILITY = 'docs/superpowers/plans/2026-10-17-scopebase-traceability.json'
DOCUMENTS = ('docs/architecture.md', 'docs/versioning.md', 'docs/contributing.md',
             'docs/security-boundaries.md', 'docs/contracts/compatibility.md',
             'docs/issues/TEMPLATE.md')
ISSUE_SECTIONS = ('Status and scope', 'Trigger and invariant', 'Selected source and license',
                  'Mechanism and destination', 'Original regression', 'Independent oracle',
                  'Known-bad control and positive twin', 'Contract references',
                  'Effects bounds and cleanup', 'Required environment and bindings',
                  'Reference consumers and delivery', 'Upstream inclusion and removal test',
                  'Migration and duplicate retirement')
GUIDE_SECTIONS = ('Prerequisites', 'Package and installed route', 'Actual consumer binding',
                  'Inputs and effects', 'Limits and failure meanings', 'Ownership and cleanup',
                  'Concurrency and fork', 'Required cases and environments',
                  'Examples and execution status', 'Sanitized support report')
SPEC = 'docs/superpowers/specs/2026-10-17-scopebase-'
PROJECT = SPEC + 'design.md'
LINUX = SPEC + 'linux-design.md'
BPF = SPEC + 'bpf-toolchain-design.md'
CAPTURE = SPEC + 'capture-design.md'
TESTING = SPEC + 'testing-design.md'
NATIVE = SPEC + 'sdk-native-design.md'
# Fixed SB03 declarations, not a copied task/profile graph or runtime schema.
DOMAINS = {
    'rust-package': ('semver', '0.1.0', 'SB02', PROJECT + '#platform-dependencies-and-compatibility-policy'),
    'neutral-semantic': ('major', '1', 'CP10', CAPTURE + '#canonical-neutral-validation-seam-for-selective-interoperability'),
    'capture-replay': ('major', '1', 'CP10', CAPTURE + '#strict-neutral-replay'),
    'native-abi': ('major', '1', 'NX07', NATIVE + '#scopebase-pure-c-abi-v1'),
    'native-wire': ('major', '1', 'NX07', NATIVE + '#scopebase-pure-c-abi-v1'),
    'run-report': ('major', '1', 'TT02', TESTING + '#result-and-verdict-contract'),
    'case-catalog': ('major', '1', 'TT01', TESTING + '#required-profiles-and-evidence-selection'),
    'case-revision': ('per_artifact', None, 'TT01', TESTING + '#required-profiles-and-evidence-selection'),
    'fixture-revision': ('per_artifact', None, 'TT01', TESTING + '#exact-public-adapter-seam'),
    'support-profile': ('per_artifact', None, 'TT01', TESTING + '#required-profiles-and-evidence-selection'),
    'documentation-registry': ('semver', '1.0.0', 'SB03', 'docs/contracts/compatibility.md#registry-and-checker-contract'),
}
ERROR_SOURCES = {
    'linux.stage': (LINUX, 'linux-stage-prose'),
    'linux.reason': (LINUX, 'linux-reason-prose'),
    'bpf.kind': (BPF, 'rust-enum:ErrorKind'),
    'bpf.stage': (BPF, 'rust-enum:Stage'),
    'capture.contract': (CAPTURE, 'rust-enum:ContractError'),
    'capture.replay': (CAPTURE, 'rust-enum:ReplayErrorKind'),
}
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z', re.ASCII)
CATEGORY = re.compile(r'[A-Za-z][A-Za-z0-9_]*\Z', re.ASCII)
SEMVER = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z')
MAJOR = re.compile(r'[1-9][0-9]*\Z')
FENCE = re.compile(r'^```scopebase-doc[ \t]*\n(.*?)^```[ \t]*$', re.M | re.S)


def decode(text):
    return json.loads(text, object_pairs_hook=unique_members,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


class Checker:
    """One local traversal with explicit bounds and deterministic diagnostics."""
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.errors = []
        self.checked = []
        self.cache = {}
        self.markdown = set()

    def fail(self, code, path, message, record=''):
        self.errors.append(dict(code=code, path=path, record=record, message=message))

    def local(self, path):
        """Normalize a local reference and check containment before any read."""
        if not isinstance(path, str) or not path or '\\' in path or '\x00' in path:
            self.fail('LINK', '', 'Expected a local repository path')
            return None
        value = Path(path)
        candidate = value if value.is_absolute() else self.root / value
        try:
            resolved = candidate.resolve()
            if not resolved.is_relative_to(self.root):
                self.fail('PATH_ESCAPE', '' if value.is_absolute() else path,
                          'Path resolves outside the selected root')
                return None
            relative = resolved.relative_to(self.root).as_posix()
        except (OSError, RuntimeError, ValueError):
            self.fail('PATH_ESCAPE', '', 'Cannot resolve path within the selected root')
            return None
        # Lexical normalization keeps report paths independent of scratch roots.
        return resolved, str(PurePosixPath(relative))

    def read(self, path, limit=DOCUMENT_LIMIT, missing='REQUIRED_MISSING'):
        location = self.local(path)
        if location is None:
            return None
        target, label = location
        key = (target, limit)
        if key in self.cache:
            return self.cache[key]
        if target.suffix == '.md' and target not in self.markdown:
            if len(self.markdown) >= DOCUMENT_LIMIT_COUNT:
                self.fail('BOUNDS', label, 'Too many checked Markdown files')
                return None
            self.markdown.add(target)
        try:
            with target.open('rb') as stream:
                raw = stream.read(limit + 1)
            if len(raw) > limit:
                self.fail('BOUNDS', label, 'Input exceeds byte limit')
                return None
            text = raw.decode('utf-8')
        except UnicodeError:
            self.fail('JSON_INPUT', label, 'Input must be UTF-8')
            return None
        except OSError:
            self.fail(missing, label, 'Required readable file is absent')
            return None
        if not text.strip():
            self.fail(missing, label, 'Required file is empty')
            return None
        self.cache[key] = text
        return text

    def json_file(self, path):
        body = self.read(path, JSON_LIMIT)
        if body is None:
            return None
        label = self.local(path)[1]
        try:
            value = decode(body)
        except (ValueError, RecursionError):
            self.fail('JSON_INPUT', label, 'Invalid JSON framing or duplicate member')
            return None
        if not isinstance(value, dict):
            self.fail('SCHEMA_TYPE', label, 'Expected a JSON object')
            return None
        return value

    def fields(self, value, fields, path, record=''):
        if not isinstance(value, dict):
            self.fail('SCHEMA_TYPE', path, 'Expected an object', record)
            return False
        if set(value) != set(fields.split()):
            self.fail('SCHEMA_FIELD', path, 'Object fields differ from the contract', record)
            return False
        return True

    def rows(self, value, path, record=''):
        if not isinstance(value, list):
            self.fail('SCHEMA_TYPE', path, 'Expected an array', record)
            return []
        if len(value) > RECORD_LIMIT:
            self.fail('BOUNDS', path, 'Array exceeds record limit', record)
            return []
        return value

    def string(self, value, path, record='', pattern=IDENTIFIER):
        if not isinstance(value, str) or not pattern.fullmatch(value):
            self.fail('SCHEMA_TYPE', path, 'Invalid identifier or string type', record)
            return False
        return True

    def link(self, value, context, record='', base=None):
        if not isinstance(value, str):
            self.fail('SCHEMA_TYPE', context, 'Link must be a string', record)
            return
        try:
            split = urlsplit(value)
        except ValueError:
            self.fail('LINK', context, 'Malformed link', record)
            return
        if split.scheme or split.netloc:
            return  # External availability is deliberately not checked.
        path, _, anchor = unquote(value).partition('#')
        if not path:
            path = context
        elif base:
            path = (PurePosixPath(base) / path).as_posix()
        location = self.local(path)
        if location is None:
            return
        target, _ = location
        relative = target.relative_to(self.root).as_posix()
        if self.read(relative, missing='LINK') is None:
            return
        # The existing helper is side-effect-free; bytes were bounded and
        # contained above. This checks its established heading-anchor grammar.
        try:
            valid = document_link(relative + ('#' + anchor if '#' in value else ''), self.root)
        except (OSError, UnicodeError):
            valid = False
        if not valid:
            self.fail('LINK', context, 'Local path or anchor does not exist', record)

    def source_categories(self, source, selector, record):
        text = self.read(source, missing='CATEGORY_SOURCE')
        if text is None:
            return None
        if selector in ('linux-stage-prose', 'linux-reason-prose'):
            label = 'Stage' if selector == 'linux-stage-prose' else 'Reason'
            matches = re.findall(r'\b' + label + r' variants cover ([^.]+)\.', text)
            if len(matches) != 1:
                self.fail('CATEGORY_SOURCE', source, 'Expected one category sentence', record)
                return None
            body = re.sub(r'\([A-Za-z][A-Za-z0-9_]*\)', '', matches[0])
            names = re.split(r',\s*|\s+and\s+', body.strip())
        else:
            name = selector.split(':', 1)[1]
            fences = re.findall(r'^```rust[^\n]*\n(.*?)^```[ \t]*$', text, re.M | re.S)
            matches = re.findall(r'\bpub enum ' + re.escape(name) + r'\s*\{([^{}]*)\}', '\n'.join(fences))
            # A second declaration with unsupported syntax is ambiguous too.
            count = len(re.findall(r'\bpub enum ' + re.escape(name) + r'\b', '\n'.join(fences)))
            if len(matches) != 1 or count != 1:
                self.fail('CATEGORY_SOURCE', source, 'Expected one simple Rust enum', record)
                return None
            names = [part.strip() for part in matches[0].strip().rstrip(',').split(',')]
        if not names or any(not CATEGORY.fullmatch(n) for n in names) or len(set(names)) != len(names):
            self.fail('CATEGORY_SOURCE', source, 'Category syntax changed or is ambiguous', record)
            return None
        return names

    def identifiers(self):
        ledger = self.json_file(TRACEABILITY)
        result = {}
        if not isinstance(ledger, dict):
            if ledger is not None:
                self.fail('SCHEMA_TYPE', TRACEABILITY, 'Expected traceability object')
            return result
        for name in ('tasks', 'requirements', 'profiles', 'profile_extensions'):
            ids = set()
            for row in self.rows(ledger.get(name), TRACEABILITY, name):
                if not isinstance(row, dict) or not self.string(row.get('id'), TRACEABILITY, name):
                    self.fail('REFERENCE', TRACEABILITY, 'Malformed identifier authority', name)
                    continue
                if row['id'] in ids:
                    self.fail('ID_DUPLICATE', TRACEABILITY, 'Duplicate authority identifier', name)
                ids.add(row['id'])
            result[name] = ids
        return result

    def registry(self, registry, ids):
        domains, errors = {}, {}
        if not self.fields(registry, 'schema_version kind domains error_domains', REGISTRY):
            return domains, errors
        if registry['schema_version'] != '1.0.0':
            self.fail('REGISTRY_VERSION', REGISTRY, 'Only registry 1.0.0 is supported')
        if registry['kind'] != 'documentation_contract_registry':
            self.fail('SCHEMA_TYPE', REGISTRY, 'Invalid registry kind')
        for row in self.rows(registry['domains'], REGISTRY, 'domains'):
            if not self.fields(row, 'id encoding version state owner_task source', REGISTRY, 'domains'):
                continue
            ident = row['id']
            if not self.string(ident, REGISTRY, 'domains'):
                continue
            if ident in domains:
                self.fail('ID_DUPLICATE', REGISTRY, 'Duplicate version domain', ident)
            domains[ident] = row
            expected = DOMAINS.get(ident)
            if expected is None:
                self.fail('REFERENCE', REGISTRY, 'Unknown version domain', ident)
                continue
            encoding, version, owner, source = expected
            actual = row['version']
            valid = ((encoding == 'per_artifact' and actual is None)
                     or (isinstance(actual, str) and (SEMVER if encoding == 'semver' else MAJOR).fullmatch(actual)))
            if not valid:
                self.fail('SCHEMA_TYPE', REGISTRY, 'Noncanonical version representation', ident)
            elif actual != version:
                self.fail('VERSION_UNSUPPORTED', REGISTRY, 'Version is outside the frozen contract', ident)
            state = 'implemented_tool_schema' if ident == 'documentation-registry' else 'planned'
            if (row['encoding'] != encoding or row['state'] != state or row['owner_task'] != owner
                    or row['source'] != source or owner not in ids.get('tasks', set())):
                self.fail('REFERENCE', REGISTRY, 'Domain declaration differs from its frozen owner/source', ident)
            self.link(row['source'], REGISTRY, ident)
        for ident in DOMAINS.keys() - domains.keys():
            self.fail('REQUIRED_MISSING', REGISTRY, 'Required version domain absent', ident)
        for row in self.rows(registry['error_domains'], REGISTRY, 'error_domains'):
            if not self.fields(row, 'id source selector categories', REGISTRY, 'error_domains'):
                continue
            ident = row['id']
            if not self.string(ident, REGISTRY, 'error_domains'):
                continue
            if ident in errors:
                self.fail('ID_DUPLICATE', REGISTRY, 'Duplicate error domain', ident)
            errors[ident] = row
            expected = ERROR_SOURCES.get(ident)
            if expected is None:
                self.fail('REFERENCE', REGISTRY, 'Unknown error domain', ident)
                continue
            if (row['source'], row['selector']) != expected:
                self.fail('CATEGORY_SOURCE', REGISTRY, 'Source/selector differs from frozen contract', ident)
                continue
            categories = self.rows(row['categories'], REGISTRY, ident)
            if any(not isinstance(n, str) or not CATEGORY.fullmatch(n) for n in categories):
                self.fail('SCHEMA_TYPE', REGISTRY, 'Invalid category identifiers', ident)
            elif len(set(categories)) != len(categories):
                self.fail('ID_DUPLICATE', REGISTRY, 'Duplicate error category', ident)
            observed = self.source_categories(*expected, ident)
            if observed is not None and categories != observed:
                self.fail('CATEGORY_DRIFT', REGISTRY, 'Ordered categories differ from source', ident)
        for ident in ERROR_SOURCES.keys() - errors.keys():
            self.fail('REQUIRED_MISSING', REGISTRY, 'Required error domain absent', ident)
        return domains, errors

    def block(self, row, path, ids, domains, errors):
        fields = ('schema_version id mode owner_task requirements versions errors profiles '
                  'subject_kind authority_claim execution')
        if not self.fields(row, fields, path):
            return None
        ident = row['id']
        if not self.string(ident, path):
            return None
        if type(row['schema_version']) is not int or row['schema_version'] != 1:
            self.fail('SCHEMA_TYPE', path, 'Expected integer doc schema 1', ident)
        if row['mode'] not in ('contract', 'template', 'illustrative'):
            self.fail('SCHEMA_TYPE', path, 'Invalid document mode', ident)
        if not isinstance(row['owner_task'], str) or row['owner_task'] not in ids.get('tasks', set()):
            self.fail('REFERENCE', path, 'Unknown owner task', ident)
        seen = set()
        for requirement in self.rows(row['requirements'], path, ident):
            if not self.string(requirement, path, ident):
                continue
            if requirement not in ids.get('requirements', set()):
                self.fail('REFERENCE', path, 'Unknown requirement', ident)
            if requirement in seen:
                self.fail('ID_DUPLICATE', path, 'Duplicate requirement', ident)
            seen.add(requirement)
        for collection, fields in (('versions', 'domain version'), ('errors', 'domain category'),
                                   ('profiles', 'id claim')):
            seen = set()
            for item in self.rows(row[collection], path, ident):
                if not self.fields(item, fields, path, ident):
                    continue
                key = item.get('domain', item.get('id'))
                if not self.string(key, path, ident):
                    continue
                unique_key = (key, item.get('category')) if collection == 'errors' else key
                if collection == 'errors' and not self.string(item['category'], path, ident, CATEGORY):
                    continue
                if unique_key in seen:
                    self.fail('ID_DUPLICATE', path, 'Duplicate ' + collection + ' reference', ident)
                seen.add(unique_key)
                if collection == 'versions':
                    if key not in domains:
                        self.fail('REFERENCE', path, 'Unknown version domain', ident)
                    elif type(item['version']) is not type(domains[key]['version']) or item['version'] != domains[key]['version']:
                        self.fail('VERSION_UNSUPPORTED', path, 'Exact registered version required', ident)
                elif collection == 'errors':
                    if key not in errors:
                        self.fail('REFERENCE', path, 'Unknown error domain', ident)
                    elif not isinstance(errors[key]['categories'], list) or item['category'] not in errors[key]['categories']:
                        self.fail('ERROR_CATEGORY', path, 'Unknown category in error domain', ident)
                else:
                    if key in ids.get('profile_extensions', set()):
                        self.fail('PROFILE_KIND', path, 'Extension cannot be a base profile', ident)
                    elif key not in ids.get('profiles', set()):
                        self.fail('PROFILE_UNKNOWN', path, 'Unknown base profile', ident)
                    if item['claim'] != 'planned':
                        self.fail('SUPPORT_CLAIM', path, 'Only planned profile references are permitted', ident)
        kind = row['subject_kind']
        if kind not in ('report', 'observation', 'live_owner', 'policy'):
            self.fail('SCHEMA_TYPE', path, 'Invalid subject kind', ident)
        elif row['authority_claim'] != ('requires_constructor' if kind == 'live_owner' else 'none'):
            self.fail('AUTHORITY_CLAIM', path, 'Authority requires its owning runtime constructor', ident)
        if row['execution'] not in ('not_applicable', 'not_run'):
            self.fail('EXECUTION_CLAIM', path, 'This format cannot claim execution', ident)
        return ident

    def sections(self, text, level):
        # Headings inside fenced examples are not document sections.
        text = re.sub(r'^(`{3,}|~{3,})[^\n]*\n.*?^\1[ \t]*$', '', text, flags=re.M | re.S)
        headings = list(re.finditer(r'^' + '#' * level + r' ([^\n]+)\n', text, re.M))
        return [(m.group(1), text[m.end():headings[i + 1].start() if i + 1 < len(headings) else len(text)])
                for i, m in enumerate(headings)]

    def document(self, path, text, ids, domains, errors):
        blocks = FENCE.findall(text)
        if len(blocks) != 1 or len(re.findall(r'^```scopebase-doc\b', text, re.M)) != 1:
            self.fail('REQUIRED_MISSING', path, 'Expected exactly one scopebase-doc block')
            ident = None
        elif len(blocks[0].encode('utf-8')) > JSON_LIMIT:
            self.fail('BOUNDS', path, 'Doc block exceeds JSON byte limit')
            ident = None
        else:
            try:
                ident = self.block(decode(blocks[0]), path, ids, domains, errors)
            except (ValueError, RecursionError):
                self.fail('JSON_INPUT', path, 'Invalid doc JSON framing or duplicate member')
                ident = None
        if path.startswith('docs/issues/'):
            sections = self.sections(text, 2)
            names = [name for name, _ in sections]
            if tuple(names) != ISSUE_SECTIONS:
                self.fail('ISSUE_SECTION', path, 'Issue requires the exact ordered H2 checklist')
            for name, body in sections:
                if name not in ISSUE_SECTIONS:
                    continue
                if not body.strip() or (path != 'docs/issues/TEMPLATE.md' and body.strip() in ('TODO', 'TBD', '<fill>')):
                    self.fail('ISSUE_CONTENT', path, 'Issue section needs substantive or explicitly unresolved content', name)
        if path == 'docs/contributing.md':
            sections = self.sections(text, 2)
            for title in ('User guide template', 'Developer guide template'):
                matching = [body for name, body in sections if name == title]
                if len(matching) != 1 or [name for name, _ in self.sections(matching[0], 3)] != list(GUIDE_SECTIONS):
                    self.fail('GUIDE_SECTION', path, 'Guide requires its own complete H3 checklist', title)
                elif any(not body.strip() for _, body in self.sections(matching[0], 3)):
                    self.fail('GUIDE_SECTION', path, 'Guide section is empty', title)
        # Simple inline/reference links only, excluding code. No Markdown execution.
        prose = re.sub(r'^(`{3,}|~{3,})[^\n]*\n.*?^\1[ \t]*$', '', text, flags=re.M | re.S)
        links = re.findall(r'\]\((<[^>\n]+>|[^\s)]+)(?:\s+"[^"]*")?\)', prose)
        links += re.findall(r'^\[[^\]]+\]:\s*(<[^>\n]+>|\S+)', prose, re.M)
        if len(links) > RECORD_LIMIT:
            self.fail('BOUNDS', path, 'Too many local/external link references')
        else:
            for link in links:
                self.link(link.strip('<>'), path, base=str(PurePosixPath(path).parent))
        return ident

    def run(self, registry):
        ids = self.identifiers()
        domains, errors = self.registry(registry, ids)
        paths = list(DOCUMENTS)
        location = self.local('docs/issues')
        if location is not None:
            directory, _ = location
            try:
                issues = []
                for path in directory.iterdir():
                    if path.suffix == '.md' and path.name not in ('README.md', 'TEMPLATE.md'):
                        issues.append('docs/issues/' + path.name)
                        if len(issues) > ISSUE_LIMIT:
                            self.fail('BOUNDS', 'docs/issues', 'Too many issue records')
                            break
                if len(issues) <= ISSUE_LIMIT:
                    paths.extend(sorted(issues))
            except OSError:
                self.fail('REQUIRED_MISSING', 'docs/issues', 'Required issue directory is absent')
        if len(paths) > DOCUMENT_LIMIT_COUNT:
            self.fail('BOUNDS', 'docs/issues', 'Too many documentation records')
            paths = paths[:DOCUMENT_LIMIT_COUNT]
        seen = set()
        for path in sorted(paths):
            text = self.read(path)
            if text is None:
                continue
            self.checked.append(path)
            ident = self.document(path, text, ids, domains, errors)
            if ident is not None:
                if ident in seen:
                    self.fail('ID_DUPLICATE', path, 'Duplicate document ID', ident)
                seen.add(ident)
        return sorted(self.errors, key=lambda d: (d['path'], d['record'], d['code'], d['message']))


def validate(root: Path, registry: dict) -> list[dict]:
    """Return sorted structural diagnostics for the complete fixed document set."""
    return Checker(root).run(registry)


class UsageParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(64, 'check_docs.py: invalid arguments\n')


def main(argv=None) -> int:
    parser = UsageParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--registry', default=REGISTRY)
    parser.add_argument('--format', choices=('json', 'text'), default='json')
    args = parser.parse_args(argv)
    checker = Checker(args.root)
    registry = checker.json_file(args.registry)
    if registry is not None:
        errors = checker.run(registry)
    else:
        errors = sorted(checker.errors, key=lambda d: (d['path'], d['record'], d['code'], d['message']))
    report = dict(schema_version=1, status='INVALID' if errors else 'VALID',
                  qualification='not_evaluated', checked_documents=sorted(checker.checked),
                  errors=errors[:DIAGNOSTIC_LIMIT], omitted_errors=max(0, len(errors) - DIAGNOSTIC_LIMIT))
    if args.format == 'json':
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for error in report['errors']:
            print(error['path'] + ': ' + error['code'] + ': ' + error['message'])
        print(report['status'] + '; qualification=not_evaluated')
    return 3 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
