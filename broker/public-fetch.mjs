import { lookup } from "node:dns/promises";
import https from "node:https";
import { BlockList, isIP } from "node:net";
import { networkInterfaces } from "node:os";
import { Readable } from "node:stream";
import { httpsEndpoint } from "./registry.mjs";

const blocked = new BlockList();
for (const [ip, bits] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
]) blocked.addSubnet(ip, bits);

export async function resolvePublic(url, resolve = lookup) {
  const host = httpsEndpoint(url).hostname;
  if (isIP(host) || host === "localhost" || host.endsWith(".localhost")) {
    throw new Error("The connector requires a public DNS hostname.");
  }
  const addresses = await resolve(host, { family: 4, all: true });
  const local = new Set(Object.values(networkInterfaces()).flat().map(entry => entry.address));
  if (!addresses.length || addresses.some(({ address }) =>
    isIP(address) !== 4 || blocked.check(address) || local.has(address))) {
    throw new Error("The connector endpoint does not resolve exclusively to public addresses.");
  }
  return addresses[0].address;
}

// Connect to the validated IP while still checking the certificate against the URL hostname.
// Every HTTP redirect fails before a second request can carry authorization.
export async function publicFetch(input, init = {}) {
  const source = new Request(input, init);
  const url = httpsEndpoint(source.url);
  const signal = AbortSignal.any([source.signal, AbortSignal.timeout(30_000)]);
  const address = await resolvePublic(url);
  const headers = Object.fromEntries(source.headers.entries());
  headers["accept-encoding"] = "identity";
  const body = source.body && Buffer.from(await source.arrayBuffer());
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const request = https.request(url, {
      signal, agent: false, family: 4, method: source.method, headers,
      lookup: (_host, options, done) => options.all
        ? done(null, [{ address, family: 4 }]) : done(null, address, 4),
    }, response => {
      const status = response.statusCode;
      if (status >= 300 && status < 400) {
        response.destroy();
        reject(new Error("Connector redirects are blocked."));
        return;
      }
      const responseHeaders = new Headers();
      for (let i = 0; i < response.rawHeaders.length; i += 2) {
        responseHeaders.append(response.rawHeaders[i], response.rawHeaders[i + 1]);
      }
      let size = 0;
      const stream = [204, 205, 304].includes(status) ? null : Readable.toWeb(response).pipeThrough(
        new TransformStream({
          transform(chunk, controller) {
            size += chunk.length;
            if (size > 4 * 1024 * 1024) throw new Error("Connector response exceeded the size limit.");
            controller.enqueue(chunk);
          },
        }),
      );
      if (stream === null) response.resume();
      const result = new Response(stream, { status, headers: responseHeaders });
      Object.defineProperty(result, "url", { value: url.href });
      resolve(result);
    });
    request.on("error", reject);
    request.end(body || undefined);
  });
}

export function scopedFetch(endpoint, oauth, fetcher = publicFetch) {
  return (input, init) => {
    const request = new Request(input, init);
    const url = httpsEndpoint(request.url).href;
    const metadata = oauth()?.authorizationServerMetadata;
    if (url !== endpoint) {
      const registration = metadata?.registration_endpoint;
      const token = metadata?.token_endpoint;
      const allowedPost = request.method === "POST" && (url === token || url === registration);
      const discovery = request.method === "GET" && !request.headers.has("authorization");
      if (!allowedPost && !discovery) throw new Error("Request is outside the credential binding.");
      if (url !== token && request.headers.has("authorization")) {
        throw new Error("Authorization is restricted to the registered resource and token endpoint.");
      }
    }
    return fetcher(request);
  };
}
