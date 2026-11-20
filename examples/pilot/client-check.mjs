// A supported application client against Talon: the official OpenAI Node SDK,
// pointed at Talon's gateway with the use-case key as its API key. Nothing
// else in the application changes.
//
//   TALON_URL=http://127.0.0.1:8080 TALON_USE_CASE_KEY=... node client-check.mjs
//
// It sends one permitted request (answered through Talon by the configured
// provider) and one request the company policy blocks (an IBAN and an email
// address): the SDK must surface Talon's refusal as an API error with HTTP
// 400 and code pii_policy_violation. Exits non-zero on any other outcome.
import OpenAI from "openai";

const { TALON_URL, TALON_USE_CASE_KEY } = process.env;
if (!TALON_URL || !TALON_USE_CASE_KEY) {
  console.error("set TALON_URL and TALON_USE_CASE_KEY");
  process.exit(2);
}
const client = new OpenAI({
  baseURL: `${TALON_URL.replace(/\/$/, "")}/v1/proxy/openai/v1`,
  apiKey: TALON_USE_CASE_KEY,
  maxRetries: 0,
});
const model = process.env.TALON_MODEL || "gpt-4o-mini";

const allowed = await client.chat.completions.create({
  model,
  messages: [{ role: "user", content: "Summarise ticket T-30 in five words." }],
});
if (!allowed.choices?.[0]?.message) {
  console.error("FAIL the permitted request returned no completion");
  process.exit(1);
}
console.log("PASS permitted request answered through Talon");

try {
  await client.chat.completions.create({
    model,
    messages: [{ role: "user", content: "Refund to IBAN DE89370400440532013000 for jan.kowalski@example.com" }],
  });
  console.error("FAIL a request with PII was not blocked");
  process.exit(1);
} catch (err) {
  if (!(err instanceof OpenAI.APIError) || err.status !== 400 || err.code !== "pii_policy_violation") {
    console.error("FAIL unexpected error for the PII request:", err?.status, err?.code, err?.message);
    process.exit(1);
  }
  console.log("PASS request with PII blocked by Talon: HTTP 400 pii_policy_violation");
}
