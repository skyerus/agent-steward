import { randomBytes, randomInt } from "node:crypto";
import { ConnectionError } from "./registry.mjs";

const browserId = /^[A-Za-z0-9_-]{43}$/;
export const pairingCookie = "__Host-sable-integration";
export const isBrowserId = id => typeof id === "string" && browserId.test(id);
export const newBrowserId = () => randomBytes(32).toString("base64url");

export class BrowserPairing {
  constructor(requester) {
    this.requester = requester;
    this.browsers = new Map();
    this.approved = null;
  }

  codeFor(browser) {
    if (!isBrowserId(browser)) throw new ConnectionError("Open the sign-in link in your browser.");
    if (this.approved) return undefined;
    if (!this.browsers.has(browser)) {
      if (this.browsers.size >= 12) this.browsers.delete(this.browsers.keys().next().value);
      let code;
      do {
        code = String(randomInt(100_000_000)).padStart(8, "0");
      } while ([...this.browsers.values()].includes(code));
      this.browsers.set(browser, code);
    }
    return this.browsers.get(browser);
  }

  confirm(requester, code) {
    if (this.requester !== requester || this.approved) {
      throw new ConnectionError("This sign-in is waiting for its requester in Discord.");
    }
    for (const [browser, expected] of this.browsers) {
      if (code === expected) {
        this.approved = browser;
        this.browsers.clear();
        return;
      }
    }
    throw new ConnectionError("The pairing code is no longer current. Open the sign-in link again.");
  }

  canContinue(browser) {
    return isBrowserId(browser) && this.approved === browser;
  }
}
