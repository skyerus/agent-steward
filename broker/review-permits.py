import concurrent.futures
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import socketserver
import struct
import threading
import time

import grpc
import ext_mcp_pb2 as api
import ext_mcp_pb2_grpc as rpc

run_dir = Path("/run/sable-review")
permit_field = "__sableReviewPermit"
context_field = "review_context_messages"
actor_field = "__sableActor"
legacy_actor_field = "__sableSignInRequester"
gateway_uid = pwd.getpwnam("sable-claw").pw_uid
permits = {}
lock = threading.Lock()
max_request = 256 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def valid_context_window(args):
    window = args.get(context_field) if isinstance(args, dict) else None
    return type(window) is int and window >= 1


def audit(service, tool, surface, outcome):
    # Never log tool arguments, integration results, turn text, or permit values.
    print(json.dumps({"service": service, "tool": tool, "surface": surface, "outcome": outcome}), flush=True)

def actor_valid(actor):
    return (
        isinstance(actor, dict) and set(actor) == {"agent", "user"}
        and isinstance(actor["agent"], str) and re.fullmatch(r"[a-z][a-z0-9_-]{0,62}", actor["agent"])
        and isinstance(actor["user"], str) and re.fullmatch(r"[0-9]{16,22}", actor["user"])
    )


def review_target(data):
    args = data.get("args", {})
    payload = {
        "service": data["service"], "name": data["name"], "actor": data["actor"],
        "fields": list(args),
        "args": {key: args[key] for key in ("id", "revision", "agentId", "audience", "repository", "guild", "channel") if key in args},
    }
    return broker_request(b"review-target", payload, 2, 8192)


def broker_request(route, payload, timeout, limit):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as broker:
        broker.settimeout(timeout)
        broker.connect("/run/sable-connection-broker.sock")
        broker.sendall(route + b"\n" + canonical(payload).encode() + b"\n")
        with broker.makefile("rb") as response:
            line = response.readline(limit + 1)
            if len(line) > limit:
                raise ValueError("oversized broker response")
            return canonical(json.loads(line)).encode() + b"\n"


class PermitIssuer(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            peer = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            pid, uid, _ = struct.unpack("3i", peer)
            if uid != gateway_uid or pid != int((run_dir / "allowed-gateway.pid").read_text().strip()):
                return
            self.request.settimeout(2)
            line = self.rfile.readline(max_request + 1)
            if len(line) > max_request:
                return
            data = json.loads(line)
            if data.get("action") == "schedule_run":
                self.request.settimeout(6)
                self.wfile.write(broker_request(b"schedule", {**data["request"], "action": "authorize_run"}, 5, 65536))
                return
            actor = data.get("actor")
            if not actor_valid(actor):
                return
            if data.get("action") == "schedule":
                scope = data["request"]["scope"]
                if scope.get("agent") != actor["agent"] or scope.get("user") != actor["user"]:
                    return
                self.request.settimeout(40)
                self.wfile.write(broker_request(b"schedule", data["request"], 38, 65536))
                return
            if data.get("action") == "target":
                self.wfile.write(review_target(data))
                return
            service, tool, args, surface = (data[key] for key in ("service", "name", "args", "surface"))
            if (not isinstance(service, str) or not 0 < len(service) <= 128 or not isinstance(tool, str) or len(tool) > 128 or
                    not valid_context_window(args) or any(key in args for key in (permit_field, actor_field, legacy_actor_field))
                    or surface not in ("voice", "text", "scheduled")):
                return
            permit = secrets.token_hex(32)
            now = time.monotonic()
            with lock:
                for key, value in list(permits.items()):
                    if value[0] <= now:
                        del permits[key]
                if len(permits) >= 256:
                    return
                permits[permit] = (now + 8, service, tool, canonical(args), surface, actor)
            self.wfile.write(permit.encode("ascii") + b"\n")
        except (OSError, ValueError, TypeError, KeyError):
            return


def denied():
    return api.McpRequestResult(error=api.AuthorizationError(
        code=api.AuthorizationError.PERMISSION_DENIED,
        reason="A current Luna approval for this exact Discord integration call is required.",
    ))


class Guard(rpc.ExtMcpServicer):
    def CheckResponse(self, response, context):
        try:
            if response.method != "tools/list" or len(response.mcp_response) > max_request:
                raise ValueError("Invalid response for review schema")
            result = json.loads(response.mcp_response)
            for tool in result["tools"]:
                schema = tool["inputSchema"]
                properties = schema.setdefault("properties", {})
                required = schema.setdefault("required", [])
                if any(key in properties or key in required
                       for key in (context_field, permit_field, actor_field, legacy_actor_field)):
                    raise ValueError("Reserved review selector collides with connector schema")
                properties[context_field] = {
                    "type": "integer", "minimum": 1,
                    "description": "How many recent user messages the reviewer needs to see. Include the original request and later clarifications. The gateway fetches the messages.",
                }
                required.append(context_field)
            return api.McpResponseResult(mutated=canonical(result).encode("utf-8"))
        except (ValueError, TypeError, KeyError, AttributeError):
            return api.McpResponseResult(error=api.AuthorizationError(
                code=api.AuthorizationError.INVALID,
                reason="Could not advertise the required review context selector.",
            ))

    def CheckRequest(self, request, context):
        if request.method != "tools/call" or len(request.service_names) != 1:
            return denied()
        service = request.service_names[0]
        try:
            if not isinstance(service, str) or not 0 < len(service) <= 128 or len(request.mcp_request) > max_request:
                return denied()
            target = json.loads(request.mcp_request)
            name, args = target["name"], target["arguments"]
            if not valid_context_window(args) or any(key in args for key in (actor_field, legacy_actor_field)):
                return denied()
            permit = args.pop(permit_field, None)
            if not isinstance(permit, str) or len(permit) != 64:
                audit(service, name, None, "denied-missing-permit")
                return denied()
            with lock:
                record = permits.pop(permit, None)
            if not record or record[0] <= time.monotonic() or record[1:4] != (service, name, canonical(args)):
                audit(service, name, None, "denied-invalid-permit")
                return denied()
            args.pop(context_field)
            args[actor_field] = record[5]
            audit(service, name, record[4], "forwarded-after-luna")
            return api.McpRequestResult(mutated=canonical(target).encode("utf-8"))
        except (ValueError, TypeError, KeyError, AttributeError):
            return denied()


socket_path = run_dir / "permits.sock"
socket_path.unlink(missing_ok=True)
with socketserver.ThreadingUnixStreamServer(str(socket_path), PermitIssuer) as issuer:
    issuer.daemon_threads = True
    os.chmod(socket_path, 0o660)
    server = grpc.server(concurrent.futures.ThreadPoolExecutor(max_workers=4))
    rpc.add_ExtMcpServicer_to_server(Guard(), server)
    if not server.add_insecure_port("127.0.0.1:17887"):
        raise RuntimeError("Cannot bind review policy")
    server.start()
    try:
        issuer.serve_forever()
    finally:
        server.stop(1).wait()
