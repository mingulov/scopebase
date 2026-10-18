# SPDX-License-Identifier: Apache-2.0
"""Independent source-tree admission bounds for SB02 source copying."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools' / 'build'))
import common as policy


class SourceCopyBoundTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def source_with_file(self, name, contents):
        source = self.root / 'source'
        source.mkdir()
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        return source

    def test_copies_real_source_tree_larger_than_json_limit_byte_exactly(self):
        payload = bytes(range(256)) * (1_045_188 // 256) + bytes(range(1_045_188 % 256))
        source = self.source_with_file('TT02133-source.bin', payload)
        (source / 'source-metadata.txt').write_bytes(b'm' * 4096)
        destination = self.root / 'copy'

        result = policy.source_copy(source, destination)

        self.assertEqual(result, destination)
        self.assertEqual((destination / 'TT02133-source.bin').read_bytes(), payload)
        self.assertEqual(policy.sha(source / 'TT02133-source.bin'),
                         policy.sha(destination / 'TT02133-source.bin'))
        self.assertGreater(sum(path.stat().st_size for path in source.rglob('*') if path.is_file()),
                           policy.MAX_JSON)

    def test_exact_source_cap_succeeds_and_next_byte_refuses_before_destination(self):
        selected_cap = 32
        with patch.object(policy, 'MAX_SOURCE_BYTES', selected_cap, create=True):
            exact_source = self.source_with_file('exact.bin', b'x' * selected_cap)
            exact_destination = self.root / 'exact-copy'
            policy.source_copy(exact_source, exact_destination)
            self.assertEqual((exact_destination / 'exact.bin').read_bytes(), b'x' * selected_cap)

            over_source = self.root / 'over-source'
            over_source.mkdir()
            (over_source / 'over.bin').write_bytes(b'y' * (selected_cap + 1))
            over_destination = self.root / 'over-copy'
            with self.assertRaisesRegex(policy.InputError, 'FIXTURE_BYTE_BOUND'):
                policy.source_copy(over_source, over_destination)
            self.assertFalse(over_destination.exists())

    def test_json_read_limit_remains_independent_at_and_over_its_boundary(self):
        exact = self.root / 'exact.json'
        exact.write_bytes(b'{}' + b' ' * (policy.MAX_JSON - 2))
        self.assertEqual(policy.read_json(exact), {})

        over = self.root / 'over.json'
        over.write_bytes(b'{}' + b' ' * (policy.MAX_JSON - 1))
        with self.assertRaisesRegex(policy.InputError, 'JSON_BOUND'):
            policy.read_json(over)


if __name__ == '__main__':
    unittest.main()
