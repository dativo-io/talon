// An existing application's client, unchanged except for two settings: the
// official OpenAI Node SDK with Talon's gateway as its base URL and the use
// case's Talon key as its API key (never the provider's key).
//
//   TALON_URL=http://127.0.0.1:8080 TALON_USE_CASE_KEY=... node client.mjs "<prompt>"
//
// Sends one chat completion and prints ONE JSON line with what the SDK saw:
//   {"ok":true,"content":"...","model":"..."}
//   {"ok":false,"status":400,"code":"pii_policy_violation","message":"..."}
// The acceptance test (tests/e2e/onboarding_test.go) asserts on that line and
// on what an independently counting upstream received. Exit code 0 when the
// SDK got an answer or an API error; 2 on a usage or transport error.
import OpenAI from "openai";

const { TALON_URL, TALON_USE_CASE_KEY, TALON_PROVIDER = "openai", TALON_MODEL = "gpt-4o-mini" } = process.env;
const prompt = process.argv[2];
if (!TALON_URL || !TALON_USE_CASE_KEY || !prompt) {
  console.error("usage: TALON_URL=... TALON_USE_CASE_KEY=... node client.mjs \"<prompt>\"");
  process.exit(2);
}

const client = new OpenAI({
  baseURL: `${TALON_URL.replace(/\/$/, "")}/v1/proxy/${TALON_PROVIDER}/v1`,
  apiKey: TALON_USE_CASE_KEY,
  maxRetries: 0,
});

try {
  const res = await client.chat.completions.create({ model: TALON_MODEL, messages: [{ role: "user", content: prompt }] });
  console.log(JSON.stringify({ ok: true, content: res.choices?.[0]?.message?.content ?? null, model: res.model }));
} catch (err) {
  if (err instanceof OpenAI.APIError) {
    console.log(JSON.stringify({ ok: false, status: err.status ?? null, code: err.code ?? null, message: String(err.message ?? "") }));
  } else {
    console.error(String(err));
    process.exit(2);
  }
}
