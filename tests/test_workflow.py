import os
import sys
import yaml
import unittest

# Make sure tools directory is on path when tests run from repository root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Provide a minimal stub for elftools so importing run_fuzz doesn't fail in test env
import types
elf_mod = types.ModuleType('elftools')
elf_mod.elf = types.ModuleType('elftools.elf')
elf_mod.elf.elffile = types.ModuleType('elftools.elf.elffile')
def _dummy_ELFFile(f):
    raise FileNotFoundError()
elf_mod.elf.elffile.ELFFile = _dummy_ELFFile
import sys as _sys
_sys.modules['elftools'] = elf_mod
_sys.modules['elftools.elf'] = elf_mod.elf
_sys.modules['elftools.elf.elffile'] = elf_mod.elf.elffile

from workflow import schedule_fuzzing_jobs, get_fuzzer_output_locations, Fuzzer


class TestWorkflow(unittest.TestCase):
    def test_get_fuzzer_output_locations(self):
        import tempfile
        tmp_path = tempfile.TemporaryDirectory()
        try:
            cfg = {
                'target_name': 't',
                'input_corpora': '/tmp/input',
                'timeout': '1h',
                'campaigns': 1,
                'fuzzers': {
                    'afl': {
                        'binaries': ['/bin/true', '/bin/true']
                    }
                }
            }

            f = Fuzzer('afl', ['/bin/true'])
            fuzzer_objs = [(f, cfg['fuzzers']['afl'])]
            base_output_dir = str(tmp_path.name)
            locs = get_fuzzer_output_locations(cfg, base_output_dir, fuzzer_objs)

            self.assertIn('afl', locs)
            self.assertTrue(os.path.isabs(locs['afl']['out_root']))
            self.assertEqual(locs['afl']['jobs_per_campaign'], max(1, len(f.binaries)))
        finally:
            tmp_path.cleanup()

    def test_schedule_dry_run(self):
        import tempfile
        tmp_path = tempfile.TemporaryDirectory()
        try:
            cfg = {
                'target_name': 'target',
                'input_corpora': '/tmp/input',
                'timeout': '1h',
                'campaigns': 1,
                'fuzzers': {
                    'afl': {
                        'binaries': [os.path.join(tmp_path.name, 'bin1')],
                        'jobs': 1
                    }
                }
            }

            cfg_path = os.path.join(tmp_path.name, 'cfg.yaml')
            with open(cfg_path, 'w') as fh:
                yaml.safe_dump(cfg, fh)
            outdir = os.path.join(tmp_path.name, 'out')
            os.makedirs(outdir, exist_ok=True)

            # Should not raise; dry_run prevents scheduling
            schedule_fuzzing_jobs(cfg_path, outdir, dry_run=True)
        finally:
            tmp_path.cleanup()


if __name__ == '__main__':
    unittest.main()
