// Prompt assembly, mirrored from src/hooksmith/prompts.py. The *text* is shared (src/hooksmith/prompts/*.txt);
// scripts/parity.ts proves both sides build byte-identical messages.

export interface Templates {
  system: string;
  user: string;
  feedback: string;
  plan: string;
  guidance: Record<string, string>;
}

export interface GenerateBody {
  finding_type: string;
  class_name: string;
  method: string;
  title: string;
  source: string;
  overload?: string[] | null;
  errors?: string[] | null;
  previous?: string | null;
  temperature?: number;
}

export interface Message {
  role: "system" | "user";
  content: string;
}

export function fill(template: string, values: Record<string, string>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_m, k: string) => values[k] ?? "");
}

// Python's repr() of a str, for the common case (no quotes or backslashes inside Frida type names).
const pyRepr = (s: string): string => `'${s}'`;

export function buildMessages(t: Templates, b: GenerateBody): Message[] {
  const guidance = t.guidance[b.finding_type] ?? "";
  const overloadLine =
    Array.isArray(b.overload) // [] is a real answer: the zero-argument overload
      ? `Overload to hook: .overload(${b.overload.map(pyRepr).join(", ")})`
      : "Overload: not specified. If the method has overloads, hook all of them via .overloads.forEach.";
  let feedback = "";
  if (b.errors && b.errors.length > 0) {
    feedback = fill(t.feedback, {
      errors: b.errors.map((e) => `- ${e}`).join("\n"),
      previous: b.previous ?? "",
    });
  }
  const user = fill(t.user, {
    class_name: b.class_name,
    method: b.method,
    overload_line: overloadLine,
    title: b.title,
    type_guidance: guidance,
    source: b.source,
    feedback,
  });
  return [
    { role: "system", content: t.system },
    { role: "user", content: user },
  ];
}

const FENCE = /```(?:javascript|js|typescript|ts)?\s*\n([\s\S]*?)```/i;

export function extractJs(raw: string): string {
  const m = FENCE.exec(raw);
  if (m) return m[1].trim();
  return raw.trim().replace(/^```\w*\s*\n/, "");
}
