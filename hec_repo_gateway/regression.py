"""Fixed gateway regression. This is not the full HEC regression suite."""
import tempfile
import unittest
from pathlib import Path
import gateway as g

class Security(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data, self.roots = g.DATA, g.source.ROOTS
        g.DATA = Path(self.tmp.name)/'data'
        self.root = Path(self.tmp.name)/'sources'
        self.root.mkdir()
        g.source.ROOTS = (str(self.root),)
    def tearDown(self):
        g.DATA, g.source.ROOTS = self.data, self.roots
        self.tmp.cleanup()
    def test_escape(self):
        for p in ['/etc/passwd', str(self.root)+'/../outside.py', str(self.root)+'/secrets.yaml', str(self.root)+'/BUILD26.py', str(self.root)+'/goodwe.py']:
            with self.assertRaises((ValueError, OSError)):
                g.source.read_allowed(p)
    def test_symlink_and_hardlink(self):
        p = self.root/'ok.py'; p.write_text('VALUE=1\n')
        s = self.root/'link.py'; s.symlink_to(p)
        with self.assertRaises(OSError):
            g.source.read_allowed(str(s))
        import os
        os.link(p, self.root/'hard.py')
        with self.assertRaises(ValueError):
            g.source.read_allowed(str(p))
    def test_source_allowlist(self):
        p=self.root/'ok.py'; p.write_text('VALUE=1\n')
        with self.assertRaises(ValueError):
            g.call('controlled_patch_source', {'path': str(p), 'sha256':g.digest(p.read_bytes()), 'old':'1', 'new':'2'})
        self.assertEqual(p.read_text(), 'VALUE=1\n')
    def test_unknown_command(self):
        for name in ['shell_exec','push','git_add_all']:
            with self.assertRaises(ValueError):
                g.call(name, {})
    def test_fixture_flow(self):
        f=g.call('fixture_create', {}); a={'session':f['session'], 'path':'fixture.py'}
        r=g.call('read_source',a)
        with self.assertRaises(ValueError):
            g.call('controlled_patch_source', {**a,'sha256':'bad','old':'1','new':'2'})
        g.call('controlled_patch_source', {**a,'sha256':r['sha256'],'old':'1','new':'2'})
        args={'session':f['session'],'paths':['fixture.py']}
        self.assertEqual(g.call('run_focused_tests',args)['status'],'PASS')
        self.assertIn('+VALUE = 2',g.call('git_diff',args)['diff'])
        self.assertEqual(g.call('git_diff_check',args)['status'],'PASS')
        for paths in [['.'],['-A'],['../fixture.py'],['fixture.py','fixture.py']]:
            with self.assertRaises(ValueError):
                g.call('git_stage_exact', {**args,'paths':paths})
        self.assertEqual(g.call('git_stage_exact',args)['staged'],['fixture.py'])
        commit=g.call('git_commit_no_push',{**args,'message':'Fixture verified'})
        self.assertFalse(commit['pushed'])
        self.assertEqual(g.call('repo_status',{'session':f['session']})['status'],'?? manifest.json\n')
    def test_full_hec_not_claimed(self):
        self.assertEqual(g.call('run_full_hec_regression',{})['status'],'BLOCKED')

if __name__ == '__main__':
    unittest.main()
