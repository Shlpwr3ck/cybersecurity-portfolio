# BSides Tampa 2026 — Conference Write-Up
## Prompt Injection, LLM Attack Surfaces, and the Emerging AI Pentest Market

**Author:** James "Jax" Jackson, Noble Technologies LLC
**Event:** BSides Tampa 2026 — May 15–16, 2026
**Location:** Tampa, FL
**Classification:** UNCLASSIFIED // PUBLIC RELEASE
**Purpose:** Professional development documentation for cybersecurity portfolio

---

## Overview

BSides Tampa 2026 marked my first attendance at this conference. Two days, multiple villages, a hardware CTF, and some of the most relevant security content I've encountered for where the threat landscape is actually heading. The standout technical session was a deep-dive on prompt injection attacks against large language models — a domain that's moving fast, largely undefended in the SMB space, and directly relevant to where Noble Technologies is positioning its service offerings.

This write-up focuses primarily on the LLM security session from May 15, with additional notes from the Saturday village track and the Offensive Village CTF.

---

## Why This Matters

Organizations are deploying AI-integrated tools at a pace that has outrun their security posture. Customer service bots, internal knowledge assistants, document summarizers, code review tools — these systems are being stood up with the same urgency that characterized early cloud adoption, and with the same lack of security rigor.

The attack surface is real and it is largely unreviewed. Most SMBs using AI tooling have had zero security assessment of those systems. There is almost no standardization in how AI pentesting is scoped or performed. For a firm like Noble Technologies that moves early on emerging service lines, this is a significant opportunity — but only if we understand the attack classes well enough to deliver credible assessments.

That's the professional context for why this session mattered.

---

## Key Concepts: LLM Attack Surface

Presenter: portfolio.pavanreddy.ai — BSides Tampa 2026
Framework: OWASP LLM Top 10

### The Core Vulnerability

The foundational problem with current LLM architecture is that the model cannot distinguish between data it is supposed to analyze and instructions it is supposed to follow. Everything lands in the same context window and gets processed the same way. This is not a bug in any one implementation — it is a structural characteristic of how these models work.

> *"The LLM cannot distinguish between data to analyze and instructions to follow — everything in context looks the same to the model."*

This single insight explains why the entire injection attack class exists and why it is so difficult to patch.

---

### Attack Class 1: Direct Injection

The user is the attacker. Malicious instructions are entered directly into the interface.

Common techniques covered:

- **Instruction override:** Classic "ignore previous instructions" phrasing — still effective against poorly hardened systems
- **Authority assertion:** Claiming elevated permissions or system-level roles within the prompt
- **Persona replacement:** Instructing the model to adopt an alternate identity that is not bound by its configured constraints
- **Social/framing attacks:** Grandma framing, nostalgia framing — emotionally-loaded contexts that reduce model resistance to policy violations

Direct injection gets the most attention because it is visible in logs and easier to conceptualize. It is also the one most defenders focus on — which is why indirect injection is more dangerous in practice.

---

### Attack Class 2: Indirect Injection

The user does not type anything malicious. The attack is embedded in content the AI retrieves and processes on the user's behalf.

Sources for indirect injection payloads:

- RAG-connected document stores
- Web pages fetched during a browsing task
- Database query results returned to an agent
- PDF attachments submitted for summarization
- API responses ingested by multi-step agent workflows

The attack is fully covert from the user's perspective. The document looks clean. The web page looks clean. The user's request is legitimate. The AI acts on hidden instructions embedded in the content it was given to process.

---

### Delivery and Obfuscation Techniques

These techniques defeat human review of source documents and bypass simple content filters:

| Technique | Mechanism |
|---|---|
| White text on white background | Invisible to human reader; parsed by AI |
| Zero-width unicode characters | Hidden between visible characters |
| Base64 / ROT13 encoding | Obfuscated payload decoded in-context |
| PDF metadata fields | Instructions embedded outside visible content |
| HTML comments | Hidden from rendered view |
| Margin text | Below visible scroll area or in document margins |

The key point: a security-conscious human reviewer examining the source document may find nothing. The AI processes what the human cannot see.

---

### Combination Attacks

Layered defenses lose effectiveness when attackers stack techniques. A payload that fails against input filtering alone may succeed when delivered via indirect injection with obfuscation and encoded instructions. Defense-in-depth is necessary precisely because single-layer controls get defeated by technique combination.

---

### Access Control Exfiltration

Even without direct data dumps, an attacker can enumerate what a system knows through binary inference — asking yes/no questions that reveal schema details, permission structures, or record existence. Techniques include:

- **Binary inference:** Questions crafted so the model's response pattern reveals restricted information
- **Role confusion:** Exploiting inconsistencies in how the model interprets its own permissions
- **Chunked requests:** Extracting restricted data in small increments across multiple interactions to stay under detection thresholds

---

### SQL Injection via AI Agent

When an AI agent translates natural language to database queries, traditional SQL injection resurfaces in a new form. The attacker does not need to know the query syntax — they craft natural language that causes the agent to generate malicious SQL. Schema enumeration becomes a natural language task.

---

### Data Exfiltration Paths

Beyond direct output, multiple covert exfiltration channels are viable:

- **Chunked exfiltration:** Data extracted in pieces across multiple interactions
- **Covert channel via tools:** Using agent tool calls (webhooks, APIs, file writes) as exfiltration vectors
- **Multi-hop agent pivoting:** Compromised agent in a chain affects downstream agents
- **Memory poisoning:** Injecting false information into persistent memory stores that shapes future model behavior

---

### EchoLeak

EchoLeak is a full attack class — external context injection leading to data exfiltration. An attacker controls content that enters the model's context (via RAG, web fetch, document upload, etc.), embeds instructions that cause the model to retrieve and transmit sensitive data, and the exfiltration occurs through normal-looking model output or tool use. The name reflects the core mechanic: what the model knows gets echoed back out through a channel the attacker controls.

---

## Live Demo Breakdown

The session included a live demonstration of the indirect injection → exfiltration chain.

**Setup:**
- A document was prepared containing white-text hidden instructions (invisible to human review)
- The document was submitted to an AI system configured with access to a backend data source
- The task given: summarize the document

**What happened:**
- The AI processed the visible document content as expected
- It also processed the hidden instructions embedded in white text
- Those instructions directed the model to retrieve data from the backend server
- The model's "summary" included that exfiltrated data, formatted to appear as part of a normal response

**Why this matters operationally:**
A document that passes human review — no obvious anomalies, no suspicious content — can carry a payload that causes an AI system to exfiltrate data without any visible indication of compromise. The user sees a summary. The attacker receives data.

This is not theoretical. The demo ran against a live environment in front of the room.

---

## Defense Framework

The presenter outlined a six-layer defense model. No single layer is sufficient; the attack classes above demonstrate how each layer can be bypassed in isolation.

| Layer | Controls |
|---|---|
| **Architecture** | Principle of least privilege for AI agents; data isolation; minimize context window access |
| **Input Controls** | Input validation and sanitization; injection signature detection; context boundary enforcement |
| **Output Controls** | Output filtering; response anomaly detection; blocking unexpected data formats in responses |
| **Monitoring** | Logging all model inputs and outputs; behavioral baseline; alerting on anomalous tool use patterns |
| **System Prompt Hardening** | Explicit role constraints; resistance to persona replacement; clear instruction hierarchy |
| **Ongoing Red Teaming** | Continuous adversarial testing against deployed systems; not a one-time assessment |

The sixth layer — ongoing red teaming — is the one most organizations skip. Point-in-time assessment does not address the dynamic nature of LLM deployments: model updates, prompt changes, new integrations, and evolving attack techniques all change the threat profile continuously.

---

## Tooling

Tools discussed for adversarial testing of LLM systems:

- **[Garak](https://github.com/NVIDIA/garak)** — LLM vulnerability scanner; covers injection, jailbreak, and data extraction test cases
- **[PyRIT](https://github.com/Azure/PyRIT)** — Python Risk Identification Toolkit for Generative AI; Microsoft's red teaming framework for AI systems
- **[OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)** — The classification framework underpinning the session; the closest thing to standardized scope that currently exists for AI security assessments

These three collectively provide the framework (OWASP), the scanner (Garak), and the red team automation platform (PyRIT) for a structured AI pentest engagement.

---

## CTF and Villages

**Saturday — Full Village Track**

Attended all villages throughout Saturday. The conference ran the standard BSides village format covering offensive security, defensive operations, social engineering, and hardware. The Offensive Village hosted the main CTF for the day.

**BSides Tampa CTF (Offensive Village)**

Worked the CTF from the Offensive Village floor on Saturday. Challenges covered the typical offensive track mix — no specific challenge solutions are documented here.

**Badge Challenge**

The conference badge included a hardware CTF component — a hex/binary blinking pattern that encoded a challenge. Hardware badge challenges at BSides events are a good hands-on reminder that embedded systems and physical security are in scope for any complete security program. The pattern recognition and decode process reinforces the same fundamentals that apply to IoT security assessments.

---

## Takeaways for Noble Technologies

**1. AI pentest is a real and growing service line.**
The market exists now. Most organizations deploying AI tools have had zero security review of those systems. There is no dominant player in SMB AI security assessment. The OWASP LLM Top 10 and the tooling above provide a credible framework to scope and deliver these engagements today.

**2. The attack surface is not hypothetical.**
The live demo demonstrated a complete attack chain — document preparation, delivery, covert execution, and data exfiltration — against a live system. These are not academic vulnerabilities. They are operational.

**3. Indirect injection is the harder problem.**
Most clients and many practitioners focus on direct injection because it is visible and intuitive. Indirect injection via RAG, document processing, and web-connected agents is harder to detect, harder to demonstrate in a sales conversation, and more dangerous in practice. That's where differentiated expertise lives.

**4. Assessments need to be ongoing, not point-in-time.**
AI systems change. Prompts change. Integrations change. Models change. A one-time security review of an AI deployment has a short shelf life. This creates opportunity for retainer-based AI security services.

**5. The BSides community is a peer network, not just a conference.**
Two days of village conversations and hallway discussions at this level produce more actionable signal than most formal training. Staying connected to this community — BSides events, village groups, CTF circuits — is worth the calendar commitment.

---

## Event Details

| | |
|---|---|
| **Conference** | BSides Tampa 2026 |
| **Dates** | May 15–16, 2026 |
| **Location** | Tampa, FL |
| **Lodging** | MacDill AFB |
| **Focus Session** | Prompt Injection Attacks on LLMs — OWASP LLM Top 10 |
| **Presenter (focus session)** | portfolio.pavanreddy.ai |
| **Activities** | Technical sessions, all villages, Offensive Village CTF, badge challenge |

---

*James "Jax" Jackson | Noble Technologies LLC | Tampa, FL*
*Cybersecurity Portfolio — Professional Development*
