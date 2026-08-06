# Governed Assistant for Azure Foundry

Minimal [Agent Governance Toolkit (AGT)](https://github.com/microsoft/agent-governance-toolkit) agent hosted on [Microsoft Azure AI Foundry](https://learn.microsoft.com/azure/ai-studio/) using the [Microsoft Agent Framework](https://github.com/microsoft/agent-framework).

The agent exposes calculator, time, file read, HTTP, and customer-update tools behind AGT 5.0 middleware with **OPA/Rego policies** at `input` and `pre_tool_call` intervention points, plus capability sandboxing, audit logging, and rogue detection.

## Project layout

```text
├── azure.yaml                              # azd manifest for Foundry deployment
├── policies/
│   ├── manifest.yaml                       # ACS manifest (intervention points, tool catalog)
│   └── rego/
│       └── governed-assistant.rego         # Rego rules for all AARM scenarios
├── policy-engine/policy/lib/               # AGT stock Rego helpers (redact, budgets, approval)
└── src/governed-assistant/
    ├── Dockerfile                          # Container image (OPA + Rego policies)
    ├── main.py                             # Foundry Responses host entry point
    ├── agent_factory.py                    # Agent + AGT middleware wiring
    ├── rego_runtime.py                     # AgtRuntime factory over ACS manifest
    ├── governance_policy.py                # Budgets, approval resolver bootstrap
    ├── tools.py                            # Tool definitions
    ├── requirements.txt
    └── tests/
        └── test_governance.py              # Offline OPA/Rego policy tests
```

## Prerequisites

- Python 3.11+ (3.13 recommended for Foundry container deploy)
- [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa) 0.69+ on `PATH` (local tests and policy validation)
- [Azure Developer CLI (`azd`)](https://learn.microsoft.com/azure/developer/azure-developer-cli/install-azd) 1.25.3+
- Foundry extension: `azd ext install microsoft.foundry`
- Azure subscription with a Foundry project (or let `azd` create one)

## 1. Local setup

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r src/governed-assistant/requirements.txt
pip install pytest pytest-asyncio   # for local tests
```

Copy environment template and fill in your Foundry project values (only needed for live local runs):

```bash
cp .env.example .env
```

## 2. Test locally (no Azure credentials)

Run offline governance tests to verify Rego policies and middleware wiring:

```bash
cd src/governed-assistant
python -m pytest tests/ -v
```

These tests confirm all AARM scenarios:

- Tool allow/deny (calculator allowed, shell blocked)
- Prompt injection denied at input
- AWS key redaction (MODIFY via native `transform` verdict)
- DEFER on ambiguous delete requests
- STEP_UP approval for `update_customer_record`
- DLP blocks external HTTP exfiltration

Optional OWASP coverage check:

```bash
agt verify
```

Validate the Rego bundle directly:

```bash
opa check policies/rego/
```

## 3. Run locally against Foundry

Authenticate and start the agent host on `http://localhost:8088`:

```bash
azd auth login
azd ai agent run
```

In another terminal, invoke the local agent:

```bash
azd ai agent invoke --local "What is 17 * 23?"
```

You can also run the host directly:

```bash
cd src/governed-assistant
python main.py
```

Required environment variables:

| Variable | Description |
|----------|-------------|
| `FOUNDRY_PROJECT_ENDPOINT` | Foundry project endpoint URL |
| `AZURE_AI_MODEL_DEPLOYMENT_NAME` | Deployed model name (e.g. `gpt-5-mini`) |
| `GOVERNANCE_MANIFEST` | Optional override path to ACS `manifest.yaml` |
| `GOVERNANCE_AUTO_APPROVE` | Set to `1` to auto-approve STEP_UP tool calls (demo only) |
| `GOVERNANCE_SESSION_INTENT` | Session intent for Scenario 15 (e.g. `read-only calculator and time only`) |
| `GOVERNANCE_CREDENTIAL_SCOPE` | Per-session credential scope for Scenario 20 (`read` or `write`) |
| `GOVERNANCE_SIGNED_AUDIT` | Set to `1` for HMAC/hash-chain audit file (Scenario 19) |
| `GOVERNANCE_AUDIT_FILE` | Path for signed audit JSONL (default `.governance-audit.jsonl`) |
| `GOVERNANCE_OTEL_AUDIT` | Mirror audit entries to OTEL logs (default `1`; set `0` to disable) |

## 4. Deploy to Azure Foundry

The agent deploys as a **container image** with OPA and Rego policies baked in.

From the repository root:

```bash
azd auth login
azd up          # provision infra + deploy (first time)
# or
azd deploy      # redeploy agent image only
```

After deployment, invoke the hosted agent:

```bash
azd ai agent invoke "What time is it in UTC?"
```

The output includes a link to the agent playground in the Foundry portal.

## Governance configuration

Policy rules are in `policies/rego/governed-assistant.rego` (evaluated via `policies/manifest.yaml` and `AgtRuntime`). Runtime configuration (budgets, approval resolver) is in `governance_policy.py`. Tool allowlists are in `tools.py` (`ALLOWED_TOOLS`).

See [AARM-SCENARIOS.md](AARM-SCENARIOS.md) for scenario-by-scenario walkthroughs and the [Azure Foundry + AGT integration guide](https://microsoft.github.io/agent-governance-toolkit/deployment/azure-foundry-agent-service/) for middleware details.

## References

- [AARM Scenarios Guide](AARM-SCENARIOS.md)
- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
- [Azure AI Foundry Agent Service Integration](https://microsoft.github.io/agent-governance-toolkit/deployment/azure-foundry-agent-service)
- [Deploy your own hosted agent (Microsoft Learn)](https://learn.microsoft.com/en-us/azure/foundry/agents/quickstarts/quickstart-deploy-own-code)
- [Open Policy Agent (OPA)](https://www.openpolicyagent.org/)
