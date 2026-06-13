# Turnkey compliance reports: from init to a signed RoPA

In this tutorial we will go from an empty directory to a downloadable GDPR Record of Processing Activities (RoPA) in one path: initialize a project with EU compliance policy packs, declare the controller identity, start the server, review framework coverage in the dashboard, and export a RoPA and an EU AI Act Annex IV pack — with every export leaving its own signed evidence record. By the end you will have seen the full compliance reporting loop without writing any code.

Everything Talon produces here is **supporting documentation**: evidence and declared facts mapped to framework articles. It is not a certification or a compliance determination.

**Prerequisites:** a `talon` binary ([install matrix](../../README.md#install)), `curl`, and optionally `jq`. No LLM API key is needed — the flow works against an empty evidence store; counts simply stay at zero until you run real traffic.

**Time:** about 15 minutes.

**Verify the full surface?** After this walkthrough, use the [end-to-end verification checklist](../guides/verify-turnkey-compliance-reports.md) (auth matrix, negative cases, FinOps cross-checks, smoke section 34).

---

## 1. See what the compliance packs offer

Talon ships curated policy packs for the EU frameworks it supports. List them first:

```bash
talon init --list-compliance
```

You will see four packs — `gdpr`, `nis2`, `dora`, `eu-ai-act` — each with a description and the articles it supports (e.g. GDPR Art. 30 record-keeping, EU AI Act Art. 12 logging). A pack is a set of policy defaults plus annotations; it configures controls that support those articles.

## 2. Initialize a project with packs applied

Create a working directory and initialize with the packs you care about. We will use GDPR and the EU AI Act:

```bash
mkdir compliance-tour && cd compliance-tour
export TALON_SECRETS_KEY=$(openssl rand -hex 32)
talon init --scaffold --name compliance-tour --compliance gdpr,eu-ai-act --skip-verify
```

(In the interactive wizard — plain `talon init` — the same choice appears as the "Apply EU compliance policy packs?" step.)

Open the generated policy and look at the header:

```bash
head -30 agent.talon.yaml
```

You will find a comment block like:

```yaml
# Compliance packs applied: gdpr, eu-ai-act
#   supports: gdpr Art. 30 — internal/evidence/store.go (signed evidence records)
#   supports: eu-ai-act Art. 12 — internal/evidence/store.go (execution logging)
#   ...
```

Each `supports:` line links an article to the Talon control that backs it. These are the same mappings the coverage report and the generated documents use, so what you read in the policy header is what the auditor-facing output will claim — nothing more.

## 3. Declare the controller identity

A RoPA combines two kinds of facts: what Talon **observed** (signed evidence: models used, denials, costs) and what only you can **declare** (who the data controller is). Add the declaration to `talon.config.yaml`:

```bash
cat >> talon.config.yaml <<'EOF'

compliance:
  controller:
    name: "Example GmbH"
    contact: "privacy@example.eu"
EOF
```

Without this block the export still works, but it flags the controller identity as a missing declaration instead of silently omitting it. See [How to clear DECLARATION MISSING blocks](../guides/ropa-declarations.md) for the full declaration schema.

## 4. Start the server

```bash
export TALON_ADMIN_KEY=$(openssl rand -hex 16)
echo "admin key: $TALON_ADMIN_KEY"
talon serve --port 8080 --gateway
```

The `--gateway` flag also mounts the FinOps metrics surface (`/api/v1/metrics`, `/gateway/dashboard`) used later in this tutorial. Without it those routes return 404 and the dashboard hides the gateway links. Declarations are re-read on each request, so you can edit `talon.config.yaml` later without restarting.

## 5. Review framework coverage in the dashboard

Open the dashboard in a browser (the query parameter is how browsers authenticate; it is moved out of the URL immediately):

```text
http://localhost:8080/dashboard?talon_admin_key=YOUR_ADMIN_KEY
```

Select the **Compliance** tab. You will see:

- **Framework coverage** — one card per framework (GDPR, EU AI Act, NIS2, DORA, ISO 27001) listing each control mapping (article, Talon control, source) with the count of signed evidence records supporting it.
- **Declaration warnings** — anything still missing for a complete RoPA or Annex IV pack. Because you declared the controller in step 3, that warning is gone; remove the block and refresh to see it appear.
- **Recent evidence** — the latest signed records in the selected tenant/agent/date scope. The filters at the top apply to the coverage counts and to every export below.

## 6. Export your first RoPA

Click **RoPA (HTML)**. The browser downloads `talon-ropa.html`: a GDPR Art. 30 Record of Processing Activities naming Example GmbH as controller, with processing activities derived from evidence and a claim note stating that the document is supporting documentation, not a completed legal filing.

The same generators are available over the admin API — useful for scripting or CI:

```bash
curl -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" -o ropa.html \
  "http://localhost:8080/v1/compliance/ropa?format=html"
curl -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" -o annex-iv.json \
  "http://localhost:8080/v1/compliance/annex-iv?format=json"
curl -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" -o gdpr-report.html \
  "http://localhost:8080/v1/compliance/report?framework=gdpr"
```

Try the **Annex IV** export too: it produces the EU AI Act technical-documentation pack and explicitly lists the Annex IV items Talon *cannot* produce (model development process, performance metrics) with their owners — Talon governs deployment, it is not the model provider.

## 7. The export itself is evidence

Every compliance export records a signed control-plane evidence record — auditors can see not only the documents but when they were generated, by which surface, and for which scope:

```bash
curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" \
  "http://localhost:8080/v1/evidence?invocation_type=control_plane&limit=10" | jq '.entries[].id'
```

You will find one record per export you performed (`compliance_export_ropa`, `compliance_export_annex_iv`, `compliance_export_report`). They also appear in the dashboard's Evidence tab.

## 8. Optional: spend in the same place

Switch to the **FinOps & Runtime** tab. With `--gateway` enabled you get budget utilization, cache statistics, and spend broken down by caller, model, and provider — empty until gateway traffic flows, populated as soon as it does. Governance and cost live on the same page because both are derived from the same signed evidence.

---

## You're done

You initialized a policy with article-annotated compliance packs, declared the controller identity, reviewed evidence-backed framework coverage, and exported auditor-facing documents that left their own audit trail.

**Next steps:**

| I want to… | Doc |
|------------|-----|
| Export and verify evidence for a real handoff | [How to export evidence for auditors](../guides/compliance-export-runbook.md) |
| Understand each policy pack in detail | [EU compliance policy packs](../guides/policy-packs.md) |
| Fill in all RoPA / Annex IV declarations | [How to clear DECLARATION MISSING blocks](../guides/ropa-declarations.md) |
| Explore the metrics API behind the FinOps tab | [Gateway dashboard reference](../reference/gateway-dashboard.md) |
| Verify the full epic end-to-end (checklist, auth matrix, regression) | [How to verify turnkey compliance reports](../guides/verify-turnkey-compliance-reports.md) |
| Understand what an evidence record contains | [Evidence store](../explanation/evidence-store.md) |
