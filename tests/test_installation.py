import importlib.util
from pathlib import Path
import tempfile
import unittest
from cyberlab.distribution import source_files

SPEC=importlib.util.spec_from_file_location('cyberlab_installer',Path(__file__).resolve().parents[1]/'scripts/install_production.py')
installer=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(installer)


class InstallationTests(unittest.TestCase):
    def test_service_paths_are_correctly_quoted_by_setting_type(self):
        unit=installer.service_unit(Path('/tmp/path with spaces/install'))
        self.assertIn('WorkingDirectory=/tmp/path with spaces/install/current\n',unit)
        self.assertIn('ExecStart="/tmp/path with spaces/install/current/.venv/bin/python"',unit)
        self.assertNotIn('WorkingDirectory="',unit)
        with self.assertRaises(ValueError): installer.service_unit(Path('/tmp/injected\nExecStart=bad'))

    def test_atomic_configuration_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); source=root/'source'; source.write_text('preserve')
            target=root/'config'; target.symlink_to(source)
            with self.assertRaises(ValueError): installer.atomic_text(target,'replace')
            self.assertEqual(source.read_text(),'preserve')

    def test_activation_refuses_unmanaged_current_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            prefix=Path(tmp); (prefix/'current').mkdir()
            (prefix/'current/keep').write_text('preserve')
            with self.assertRaises(ValueError): installer.activate(prefix,prefix/'release',{})
            self.assertEqual((prefix/'current/keep').read_text(),'preserve')

    def test_installation_refuses_to_claim_unmanaged_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            prefix=Path(tmp); (prefix/'start.sh').write_text('user file')
            with self.assertRaises(ValueError): installer.claim_prefix(prefix)
            self.assertEqual((prefix/'start.sh').read_text(),'user file')
        with tempfile.TemporaryDirectory() as tmp:
            prefix=Path(tmp); installer.claim_prefix(prefix); installer.claim_prefix(prefix)
            self.assertEqual((prefix/'.cyberlab-installation').read_text(),'cyberlab-managed-install-v1\n')

    def test_activation_keeps_previous_release_and_matching_configuration(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            prefix=Path(tmp); old=prefix/'releases/old'; new=prefix/'releases/new'
            old.mkdir(parents=True); new.mkdir()
            (old/'deployment.json').write_text('{"data_dir":"old"}')
            (prefix/'current').symlink_to(old)
            installer.activate(prefix,new,{'data_dir':'new'})
            self.assertEqual((prefix/'current').resolve(),new)
            self.assertEqual((prefix/'previous').resolve(),old)
            self.assertEqual(json.loads((new/'deployment.json').read_text())['data_dir'],'new')
            self.assertEqual(json.loads((old/'deployment.json').read_text())['data_dir'],'old')

    def test_distribution_rejects_tampered_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'vendor').mkdir(); (root/'vendor/runtime.whl').write_bytes(b'tampered')
            (root/'requirements.txt').write_text('--hash=sha256:'+'0'*64)
            with self.assertRaisesRegex(ValueError,'checksum'): source_files(root)


if __name__=='__main__': unittest.main()
