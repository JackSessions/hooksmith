import system from "../../src/hooksmith/prompts/system.txt";
import user from "../../src/hooksmith/prompts/user.txt";
import feedback from "../../src/hooksmith/prompts/feedback.txt";
import plan from "../../src/hooksmith/prompts/plan.txt";
import hardcodedKey from "../../src/hooksmith/prompts/hardcoded_key.txt";
import cleartextHttp from "../../src/hooksmith/prompts/cleartext_http.txt";
import insecureRandom from "../../src/hooksmith/prompts/insecure_random.txt";
import tlsTrustAll from "../../src/hooksmith/prompts/tls_trust_all.txt";
import hostnameVerifier from "../../src/hooksmith/prompts/hostname_verifier.txt";
import { buildMessages, extractJs, type GenerateBody, type Templates } from "./prompt";

interface Env {
  AI: Ai;
  HOOKSMITH_TOKEN: string;
  MODEL: string;
  MAX_SOURCE_CHARS: string;
}

const TEMPLATES: Templates = {
  system,
  user,
  feedback,
  plan,
  guidance: {
    hardcoded_key: hardcodedKey,
    cleartext_http: cleartextHttp,
    insecure_random: insecureRandom,
    tls_trust_all: tlsTrustAll,
    hostname_verifier: hostnameVerifier,
  },
};

const json = (data: unknown, status = 200): Response =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });

// Constant-time comparison so the bearer token cannot be guessed byte by byte.
function safeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const x = enc.encode(a);
  const y = enc.encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

const isStr = (v: unknown): v is string => typeof v === "string";

function parseGenerate(body: any, max: number): GenerateBody | string {
  if (!body || typeof body !== "object") return "body must be a JSON object";
  for (const k of ["finding_type", "class_name", "method", "title", "source"]) {
    if (!isStr(body[k])) return `${k} must be a string`;
  }
  if (body.source.length > max) return `source exceeds ${max} characters`;
  if (!/^[\w.$]+$/.test(body.class_name)) return "class_name has invalid characters";
  if (!/^[\w$<>]+$/.test(body.method)) return "method has invalid characters";
  for (const k of ["overload", "errors"]) {
    if (body[k] != null && !(Array.isArray(body[k]) && body[k].every(isStr))) return `${k} must be a string array`;
  }
  const t = typeof body.temperature === "number" ? Math.min(Math.max(body.temperature, 0), 1) : 0.1;
  return { ...body, temperature: t };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/healthz") return json({ ok: true, model: env.MODEL });
    if (request.method !== "POST") return json({ error: "POST only" }, 405);

    const auth = request.headers.get("authorization") ?? "";
    if (!env.HOOKSMITH_TOKEN || !safeEqual(auth, `Bearer ${env.HOOKSMITH_TOKEN}`)) {
      return json({ error: "unauthorized" }, 401);
    }

    let body: any;
    try {
      body = await request.json();
    } catch {
      return json({ error: "invalid JSON" }, 400);
    }

    try {
      if (url.pathname === "/v1/generate") {
        const parsed = parseGenerate(body, Number(env.MAX_SOURCE_CHARS) || 20000);
        if (isStr(parsed)) return json({ error: parsed }, 400);
        const out = (await env.AI.run(env.MODEL as keyof AiModels, {
          messages: buildMessages(TEMPLATES, parsed),
          temperature: parsed.temperature ?? 0.1,
          max_tokens: 2048,
        } as any)) as { response?: string };
        const raw = out.response ?? "";
        return json({ hook: extractJs(raw), raw, model: env.MODEL });
      }

      if (url.pathname === "/v1/plan") {
        const b = body ?? {};
        const user =
          `Package: ${String(b.package ?? "")}\nTarget class: ${String(b.class_name ?? "")}\n` +
          `Finding type: ${String(b.finding_type ?? "")}\n` +
          `Declared deep links: ${JSON.stringify(b.deep_links ?? [])}\n` +
          `Exported activities: ${JSON.stringify(b.activities ?? [])}\n` +
          `Default plan: ${JSON.stringify(b.default ?? [])}\nPropose a better plan as a JSON array.`;
        const out = (await env.AI.run(env.MODEL as keyof AiModels, {
          messages: [
            { role: "system", content: TEMPLATES.plan },
            { role: "user", content: user },
          ],
          temperature: 0.2,
          max_tokens: 400,
        } as any)) as { response?: string };
        const m = /\[[\s\S]*\]/.exec(out.response ?? "");
        let steps: unknown = [];
        try {
          steps = m ? JSON.parse(m[0]) : [];
        } catch {
          steps = [];
        }
        return json({ steps: Array.isArray(steps) ? steps.map(String).slice(0, 20) : [], model: env.MODEL });
      }
      return json({ error: "not found" }, 404);
    } catch (err) {
      // Never leak internals; the CLI marks the finding UNVALIDATED with this reason.
      return json({ error: "model call failed", detail: String((err as Error)?.message ?? err).slice(0, 200) }, 502);
    }
  },
} satisfies ExportedHandler<Env>;
