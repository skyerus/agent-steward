"""Allocate a workspace for the trusted local provisioning service."""
import json
import os
from pathlib import Path
import pwd
import re
import socket
import secrets
import stat
import struct
import sys

WORKSPACES = Path("/var/lib/sable-codex/workspaces")
AGENT_ID = re.compile(r"[a-z][a-z0-9_-]{0,62}")
SHARED_DOCUMENTS = ("IDENTITY.md", "AGENTS.md")
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def prepare_workspace(base, agent, worker_uid, gateway_uid, gateway_gid, action, *, filename=None, source=None):
    if not isinstance(agent, str) or not AGENT_ID.fullmatch(agent):
        raise ValueError("Invalid agent ID")
    if action not in {"allocate", "share-documents", "deploy-connector"}:
        raise ValueError("Invalid workspace operation")
    parent = os.open(base, DIRECTORY_FLAGS)
    try:
        current = os.fstat(parent)
        if current.st_uid != 0 or current.st_mode & 0o022:
            raise PermissionError("Native workspace root is not protected")
        created = False
        if action == "allocate":
            try:
                os.mkdir(agent, 0o700, dir_fd=parent)
                created = True
            except FileExistsError:
                pass
        try:
            child = os.open(agent, DIRECTORY_FLAGS, dir_fd=parent)
            try:
                if created:
                    os.fchown(child, worker_uid, gateway_gid)
                    # On Linux a chown can clear setgid; restore it on this new inode.
                    os.fchmod(child, 0o2770)
                current = os.fstat(child)
                if (current.st_uid, current.st_gid, stat.S_IMODE(current.st_mode)) != (
                    worker_uid, gateway_gid, 0o2770,
                ):
                    raise PermissionError("Unexpected native workspace ownership")
                if action == "share-documents":
                    share_documents(child, worker_uid, gateway_uid, gateway_gid)
                if action == "deploy-connector":
                    deploy_connector(child, worker_uid, gateway_gid, filename, source)
            finally:
                os.close(child)
        except (OSError, ValueError):
            if created:
                os.rmdir(agent, dir_fd=parent)
            raise
    finally:
        os.close(parent)


def share_documents(workspace, worker_uid, gateway_uid, gateway_gid):
    for name in SHARED_DOCUMENTS:
        try:
            file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=workspace)
        except FileNotFoundError:
            continue
        try:
            current = os.fstat(file)
            if (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
                    or current.st_uid not in {worker_uid, gateway_uid}):
                raise PermissionError("Unexpected workspace document")
            os.fchown(file, worker_uid, gateway_gid)
            os.fchmod(file, 0o660)
        finally:
            os.close(file)


def deploy_connector(workspace, worker_uid, gateway_gid, filename, source):
    if (not isinstance(filename, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}\.(py|mjs|sh)", filename) or
            not isinstance(source, str) or not source.strip() or len(source) > 12000 or "\x00" in source):
        raise ValueError("Invalid connector source or filename")
    directory = ".agent-connectors"
    created = False
    try:
        os.mkdir(directory, 0o750, dir_fd=workspace)
        created = True
    except FileExistsError:
        pass
    fd = os.open(directory, DIRECTORY_FLAGS, dir_fd=workspace)
    try:
        info = os.fstat(fd)
        if info.st_uid not in {0, worker_uid} or info.st_gid != gateway_gid or info.st_mode & 0o022:
            raise PermissionError("Unexpected connector directory ownership")
        if created:
            if info.st_uid != 0:
                raise PermissionError("The connector directory changed during creation")
            os.fchown(fd, worker_uid, gateway_gid)
            os.fchmod(fd, 0o750)
        temporary = ".upload-" + secrets.token_hex(16)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            with os.fdopen(os.open(temporary, flags, 0o600, dir_fd=fd), "wb") as stream:
                stream.write(source.encode())
                stream.flush()
                os.fchown(stream.fileno(), worker_uid, gateway_gid)
            # Replace directory entries. An existing symlink is never followed.
            os.replace(temporary, filename, src_dir_fd=fd, dst_dir_fd=fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=fd)
            except FileNotFoundError:
                pass
    finally:
        os.close(fd)


def identities():
    worker = pwd.getpwnam("sable-codex")
    gateway = pwd.getpwnam("sable-claw")
    return worker.pw_uid, gateway.pw_uid, gateway.pw_gid


def main():
    worker_uid, gateway_uid, gateway_gid = identities()
    if sys.argv[1:] == ["--allocate-integration-admin"]:
        prepare_workspace(WORKSPACES, "integration-admin", worker_uid, gateway_uid, gateway_gid, "allocate")
        return
    with socket.socket(fileno=os.dup(0)) as client:
        size = struct.calcsize("3i")
        _, peer_uid, _ = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size))
        client.settimeout(2)
        try:
            if peer_uid != gateway_uid:
                raise PermissionError("Request must come from the provisioning service")
            with client.makefile("rb") as stream:
                line = stream.readline(65_537)
            if not line.endswith(b"\n"):
                raise ValueError("Invalid workspace request")
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("Invalid workspace request")
            fields = {"filename", "source"} if request.get("action") == "deploy-connector" else set()
            if set(request) != {"agent", "action"} | fields:
                raise ValueError("Invalid workspace request")
            prepare_workspace(WORKSPACES, request["agent"], worker_uid, gateway_uid, gateway_gid, request["action"],
                              **{field: request[field] for field in fields})
            response = b'{"ok":true}\n'
        except (OSError, ValueError, TypeError):
            response = b'{"ok":false}\n'
        client.sendall(response)


if __name__ == "__main__":
    main()
