// Proves the Worker builds exactly the same LLM messages as the Python side.
// Usage (from worker/): npm run parity   -> prints JSON for scripts/check_parity.py to compare.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildMessages, extractJs, type Templates } from "../src/prompt";

const dir = join(dirname(fileURLToPath(import.meta.url)), "../../src/hooksmith/prompts");
const rd = (n: string) => readFileSync(join(dir, n), "utf8");
const t: Templates = {
  system: rd("system.txt"),
  user: rd("user.txt"),
  feedback: rd("feedback.txt"),
  plan: rd("plan.txt"),
  guidance: {
    hardcoded_key: rd("hardcoded_key.txt"),
    cleartext_http: rd("cleartext_http.txt"),
    insecure_random: rd("insecure_random.txt"),
    tls_trust_all: rd("tls_trust_all.txt"),
    hostname_verifier: rd("hostname_verifier.txt"),
  },
};
const cases = JSON.parse(readFileSync(0, "utf8")) as any[];
console.log(
  JSON.stringify(
    cases.map((c) => ({ messages: buildMessages(t, c), js: extractJs(c.raw ?? "") })),
  ),
);
