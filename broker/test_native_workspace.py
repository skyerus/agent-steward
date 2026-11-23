import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


workspace = load("native-workspace")
provisioner = load("provision-agents")
REQUEST = {"name": "create_agent", "requester": "111111111111111111",
           "args": {"agentId": "fixture", "name": "Fixture"}}


@unittest.skipUnless(os.geteuid() == 0, "requires Linux workspace ownership changes")
class NativeWorkspaceTest(unittest.TestCase):
    def test_allocation_and_sharing_are_retryable(self):
        worker, gateway, group = workspace.identities()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            action = lambda kind: workspace.prepare_workspace(base, "fixture", worker, gateway, group, kind)
            action("allocate")
            action("allocate")
            directory = base / "fixture"
            self.assertEqual(directory.stat().st_uid, worker)
            self.assertEqual(directory.stat().st_gid, group)
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o2770)
            instructions = directory / "AGENTS.md"
            instructions.write_text("Use this workspace.")
            os.chown(instructions, gateway, group)
            action("share-documents")
            action("share-documents")
            self.assertEqual(instructions.stat().st_uid, worker)
            self.assertEqual(stat.S_IMODE(instructions.stat().st_mode), 0o660)
            self.assertEqual(instructions.read_text(), "Use this workspace.")

    def test_rejects_untrusted_paths_and_links(self):
        worker, gateway, group = workspace.identities()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            (base / "link").symlink_to(base, target_is_directory=True)
            for identity in ("../fixture", "link"):
                with self.subTest(identity=identity), self.assertRaises((ValueError, OSError)):
                    workspace.prepare_workspace(base, identity, worker, gateway, group, "allocate")
            workspace.prepare_workspace(base, "fixture", worker, gateway, group, "allocate")
            outside = base / "original.md"
            outside.write_text("unchanged")
            os.chown(outside, gateway, group)
            document = base / "fixture/AGENTS.md"
            for make_link in (document.symlink_to, lambda target: os.link(target, document)):
                make_link(outside)
                with self.assertRaises(OSError):
                    workspace.prepare_workspace(base, "fixture", worker, gateway, group, "share-documents")
                self.assertEqual(outside.stat().st_uid, gateway)
                document.unlink()


    def test_deployment_cannot_follow_links_and_only_installs_source(self):
        worker, gateway, group = workspace.identities()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            workspace.prepare_workspace(base, "fixture", worker, gateway, group, "allocate")
            target = base / "fixture" / ".agent-connectors"
            outside = base / "example.py"
            outside.write_text("outside stays unchanged")
            target.symlink_to(base, target_is_directory=True)

            def deploy(filename, source):
                workspace.prepare_workspace(base, "fixture", worker, gateway, group, "deploy-connector",
                                            filename=filename, source=source)

            with self.assertRaises(OSError):
                deploy("example.py", "assert False")
            target.unlink()
            previous = os.umask(0o077)
            try:
                deploy("example.py", "assert False")
            finally:
                os.umask(previous)
            installed = target / "example.py"
            self.assertEqual(target.stat().st_uid, worker)
            self.assertEqual(installed.stat().st_uid, worker)
            self.assertEqual(installed.read_text(), "assert False")
            self.assertFalse(installed.stat().st_mode & 0o111)
            installed.unlink()
            installed.symlink_to(outside)
            deploy("example.py", "print('new source')")
            self.assertFalse(installed.is_symlink())
            self.assertEqual(outside.read_text(), "outside stays unchanged")
            with self.assertRaises(ValueError):
                deploy("../example.py", "bad")


class ProvisionerTest(unittest.TestCase):
    def test_publishes_only_after_allocating_worker_workspace(self):
        created = {"agents": {"entries": {"fixture": {"name": "Fixture", "workspace": str(provisioner.WORKSPACES / "fixture")}}}}
        with patch.object(provisioner, "configuration", side_effect=[{}, created]),              patch.object(provisioner, "require_admin"),              patch.object(provisioner, "provision_workspace") as allocate,              patch.object(provisioner, "rpc") as rpc:
            trace = unittest.mock.MagicMock()
            trace.attach_mock(allocate, "workspace")
            trace.attach_mock(rpc, "rpc")
            self.assertEqual(provisioner.execute(REQUEST)["id"], "fixture")
            self.assertEqual(trace.mock_calls, [
                unittest.mock.call.workspace("fixture", "allocate"),
                unittest.mock.call.rpc("agents.create", {"agentId": "fixture", "name": "Fixture",
                                                         "workspace": str(provisioner.WORKSPACES / "fixture")}),
                unittest.mock.call.workspace("fixture", "share-documents"),
            ])

    def test_refuses_to_claim_an_existing_legacy_workspace(self):
        legacy = {"agents": {"entries": {"fixture": {"name": "Fixture", "workspace": "/tmp/legacy"}}}}
        with patch.object(provisioner, "configuration", return_value=legacy),              patch.object(provisioner, "require_admin"),              patch.object(provisioner, "rpc") as rpc:
            with self.assertRaises(provisioner.ProvisionError):
                provisioner.execute(REQUEST)
            rpc.assert_not_called()


if __name__ == "__main__":
    unittest.main()
