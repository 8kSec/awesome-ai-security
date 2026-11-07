# Awesome AI Security

> A practitioner-focused reference for AI/ML security — attacks, tools, research, and defenses. Covers the full spectrum: offensive AI, securing AI systems, AI-assisted security operations, and governance. Last updated March 28, 2026.

---

## Contents

- [1. Attacks & Exploitation](#1-attacks--exploitation)
  - [Prompt Injection](#prompt-injection)
  - [Jailbreaking LLMs](#jailbreaking-llms)
  - [Agentic & Multi-Agent Attacks](#agentic--multi-agent-attacks)
  - [Training Data & Privacy Attacks](#training-data--privacy-attacks)
  - [Adversarial ML — Classical Models](#adversarial-ml--classical-models)
  - [Supply Chain & Model Poisoning](#supply-chain--model-poisoning)
  - [AI Infrastructure Attacks](#ai-infrastructure-attacks)
  - [Offensive Use of AI](#offensive-use-of-ai)
  - [Attack Tutorials & Walkthroughs](#attack-tutorials--walkthroughs)
- [2. Key Research Papers](#2-key-research-papers)
  - [Prompt Injection & Jailbreaking](#prompt-injection--jailbreaking-papers)
  - [Privacy & Extraction](#privacy--extraction-papers)
  - [Agent Security](#agent-security-papers)
  - [Adversarial ML & Robustness](#adversarial-ml--robustness-papers)
  - [Backdoors & Supply Chain](#backdoors--supply-chain-papers)
  - [Offensive AI](#offensive-ai-papers)
  - [Defenses](#defense-papers)
- [3. Conference Talks](#3-conference-talks)
  - [Black Hat](#black-hat)
  - [RSA Conference](#rsa-conference)
  - [DEF CON AI Village](#def-con-ai-village)
  - [USENIX Security](#usenix-security)
  - [IEEE SaTML](#ieee-satml)
  - [CAMLIS](#camlis)
  - [Talk Archives on YouTube](#talk-archives-on-youtube)
- [4. Tools — Offense & Red Teaming](#4-tools--offense--red-teaming)
  - [LLM Red Teaming](#llm-red-teaming)
  - [Adversarial ML](#adversarial-ml-tools)
  - [Agentic & MCP Attack Tools](#agentic--mcp-attack-tools)
  - [Benchmarks & Evaluation](#benchmarks--evaluation)
  - [Vulnerable Labs & CTFs](#vulnerable-labs--ctfs)
- [5. Tools — Defense & Detection](#5-tools--defense--detection)
  - [Guardrails & Output Safety](#guardrails--output-safety)
  - [Model & Supply Chain Security](#model--supply-chain-security)
  - [Production Monitoring](#production-monitoring)
  - [Agent Runtime Security & Sandboxing](#agent-runtime-security--sandboxing)
  - [MCP Security](#mcp-security)
  - [AI Code Security](#ai-code-security)
  - [Privacy-Preserving Inference](#privacy-preserving-inference)
- [6. AI for Security Operations](#6-ai-for-security-operations)
  - [Penetration Testing & Offensive Security](#penetration-testing--offensive-security)
  - [Malware Analysis & Reverse Engineering](#malware-analysis--reverse-engineering)
  - [Vulnerability Research](#vulnerability-research)
  - [Threat Intelligence & SOC](#threat-intelligence--soc)
  - [Security-Specialized Models](#security-specialized-models)
- [7. Notable Incidents & CVEs](#7-notable-incidents--cves)
- [8. Attack Frameworks & Knowledge Bases](#8-attack-frameworks--knowledge-bases)
- [9. Defensive Frameworks & Standards](#9-defensive-frameworks--standards)
  - [Risk Management](#risk-management)
  - [Verification Standards](#verification-standards)
  - [Threat Modeling](#threat-modeling)
  - [Incident Response](#incident-response)
- [10. Regulatory & Compliance](#10-regulatory--compliance)
- [11. Community & Practice](#11-community--practice)
  - [Communities & Organizations](#communities--organizations)
  - [Key Practitioners to Follow](#key-practitioners-to-follow)
  - [Conferences & Venues](#conferences--venues)
  - [Bug Bounty Programs](#bug-bounty-programs)
  - [Research Blogs Worth Following](#research-blogs-worth-following)
  - [Newsletters & Podcasts](#newsletters--podcasts)
- [Datasets](#datasets)
  - [Safety & Attack Datasets](#safety--attack-datasets)
  - [Cybersecurity Skill Benchmarks](#cybersecurity-skill-benchmarks)
- [Agentic AI Security Skills](#agentic-ai-security-skills)

---

## 1. Attacks & Exploitation

### Prompt Injection

Prompt injection is the primary attack class against LLM-integrated applications. It splits into two types: **direct injection** (user-controlled input manipulates the model) and **indirect injection** (malicious instructions arrive via data the model retrieves — web pages, documents, tool outputs, emails).

**Key attack techniques:**

| Technique | What It Does | Research / Reference |
|-----------|-------------|----------------------|
| **Indirect Prompt Injection** | Attacker embeds instructions in external data (web pages, emails, documents) that a model retrieves and acts on — without the user knowing. Enables data exfiltration, unauthorized actions. | Greshake et al., 2023 — [arXiv:2302.12173](https://arxiv.org/abs/2302.12173) |
| **Second-Order Injection** | Malicious payload is stored (in a DB, email, memory) and triggers on a future retrieval — not the initial request. Survives session resets. | Common in agentic systems with persistent memory |
| **P2SQL Injection** | Prompt injection that routes through an LLM-to-SQL translator, turning natural language into malicious SQL. Different from classic SQLi. | Pedro, Castro et al., 2023 — [arXiv:2308.01990](https://arxiv.org/abs/2308.01990) |
| **Encoding / Obfuscation Bypasses** | Base64, Unicode homoglyphs, zero-width characters, multi-layer encoding, language switching — used to evade content filters that block plaintext injection strings. | [ARC PI Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy) — evasion dimension |
| **Token Budget Exhaustion** | Floods the context window to push out system prompt instructions or safety context. | Relevant for fixed-context deployments |
| **HouYi Framework** | Three-phase injection: disrupt context → inject payload → deliver. Structured methodology for constructing injection chains. | Liu et al., 2023 — [arXiv:2306.05499](https://arxiv.org/abs/2306.05499) |
| **Crescendo (Multi-Turn)** | Gradually escalates a conversation from benign to harmful over 3–5 turns. Exploits the LLM's tendency to maintain topic coherence with its own prior outputs. Crescendomation automates this. | [arXiv:2404.01833](https://arxiv.org/abs/2404.01833) |
| **Many-Shot Jailbreaking** | Fills long context windows with many examples of harmful Q&A, exploiting in-context learning against aligned models. Power-law relationship between shot count and success rate. | Anthropic, 2024 — [anthropic.com](https://www.anthropic.com/research/many-shot-jailbreaking) |

**Real-world vulnerabilities:**

- **[CVE-2025-53773](https://nvd.nist.gov/vuln/detail/CVE-2025-53773)** — GitHub Copilot RCE via prompt injection. Attacker-controlled code comments triggered Copilot to generate and execute malicious code.
- **EchoLeak ([CVE-2025-32711](https://nvd.nist.gov/vuln/detail/CVE-2025-32711))** — Zero-click prompt injection in Microsoft 365 Copilot. Chains XPIA classifier bypass + Markdown redaction bypass + auto-fetched image abuse to exfiltrate SharePoint/Teams/OneDrive data without user interaction. CVSS 9.3.
- **SpAIware** — Persistent memory injection attack in ChatGPT's memory feature. Attacker embeds instructions in a webpage; when a user asks ChatGPT to summarize it, the instructions persist in memory and activate in future sessions (Johann Rehberger / embracethered.com). [Write-up](https://embracethered.com/blog/posts/2024/chatgpt-macos-app-persistent-data-exfiltration/)

**2026 developments:**

- **ToxicSkills (Feb 2026)** — First coordinated malware campaign via AI agent skills. Snyk audited 3,984 skills from ClawHub; 36% contained prompt injection techniques, 76 confirmed malicious payloads for credential theft and SSH key exfiltration. Three lines of markdown in SKILL.md were sufficient to exfiltrate SSH keys. [snyk.io/blog](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)
- **Agentic browser injection (Trail of Bits, Jan 2026)** — Agentic browsers that fetch web pages, read files, and interact with the DOM create XSS/CSRF-equivalent attack surfaces. Magic link authentication URL attacks silently log users into attacker-controlled accounts when an agent summarizes a malicious page. [blog.trailofbits.com](https://blog.trailofbits.com/2026/01/13/lack-of-isolation-in-agentic-browsers-resurfaces-old-vulnerabilities/)
- **AI Recommendation Poisoning (Microsoft, Feb 2026)** — Microsoft documented 50+ real-world cases of prompt injection poisoning AI assistant memory (ChatGPT, Copilot, Claude, Perplexity, Grok) for commercial promotion. 31 companies across 14 industries were exploiting this in the wild. [microsoft.com/security/blog](https://www.microsoft.com/en-us/security/blog/2026/02/10/ai-recommendation-poisoning/)
- **Perplexity Comet injection (Trail of Bits, Feb 2026)** — Audit of Perplexity's Comet browser AI assistant found four prompt injection techniques that could exfiltrate private Gmail data. [blog.trailofbits.com](https://blog.trailofbits.com/2026/02/20/using-threat-modeling-and-prompt-injection-to-audit-comet/)
- **Reprompt (Varonis, Mar 2026)** — Single-link attack against Microsoft Copilot that bypasses data-leak protections and enables persistent session exfiltration even after Copilot is closed. [varonis.com/blog](https://www.varonis.com/blog/reprompt)

**Classification:**

- [ARC Prompt Injection Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy) — The most structured open classification of prompt injection attacks. Four dimensions: attacker intent (13 categories), execution technique (18), filter evasion method (20), input surface. Interactive frontend: https://arcanum-sec.github.io/arc_pi_taxonomy/

- [Promptware Kill Chain (2025)](https://arxiv.org/abs/2601.09625) — Documents 21 real-world prompt injection incidents from 2025, classifying them via a kill-chain model. Finds persistence capabilities in 12 of 21 attacks.

---

### Jailbreaking LLMs

Jailbreaking bypasses the safety alignment of a model to elicit policy-violating outputs. Distinct from prompt injection (which hijacks an integrated application); jailbreaking targets the model's trained refusal behavior directly.

**Gradient-based attacks (white-box):**

- **GCG (Greedy Coordinate Gradient)** — Optimizes a universal adversarial suffix that reliably bypasses aligned LLMs and transfers across models including GPT-4, Claude, Bard. Foundational paper: [arXiv:2307.15043](https://arxiv.org/abs/2307.15043). Production implementation: [BrokenHill](https://github.com/BishopFox/BrokenHill) (Bishop Fox).
- **AutoDAN** — Automated generation of human-readable adversarial prompts using genetic algorithms. Produces jailbreaks that are fluent and harder to detect than GCG suffixes. [github.com/SheltonLiu-N/AutoDAN](https://github.com/SheltonLiu-N/AutoDAN)
- **DiffusionAttacker** — Uses a seq2seq diffusion model to generate jailbreak prompts. Outperforms prior methods on fluency, diversity, and attack success rate. EMNLP 2025. [arXiv:2412.17522](https://arxiv.org/abs/2412.17522)

**Black-box attacks (query-only):**

- **PAIR (Prompt Automatic Iterative Refinement)** — An LLM-as-attacker that iteratively refines jailbreak prompts until a target model complies. Achieves jailbreaks in ~20 queries. [arXiv:2310.08419](https://arxiv.org/abs/2310.08419)
- **TAP (Tree of Attacks with Pruning)** — Extends PAIR with a tree search to prune ineffective attack branches. More efficient than PAIR on complex safety categories. [github.com/RICommunity/TAP](https://github.com/RICommunity/TAP)
- **Bad Likert Judge** — Instructs the target LLM to evaluate harmfulness on a Likert scale, then requests examples aligned to the highest-rated category. Boosts success rates >60% across tested models. Palo Alto Unit 42, 2024. [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/multi-turn-technique-jailbreaks-llms/)
- **Crescendo** — Multi-turn gradual escalation. See [Prompt Injection](#prompt-injection) section above.
- **Many-Shot** — Long-context exploitation. See [Prompt Injection](#prompt-injection) section above.

**Reasoning model attacks:**

- **H-CoT (Chain-of-Thought Hijacking)** — Universal attack on o1/o3, DeepSeek-R1, and Gemini 2.0 Flash Thinking that hijacks the model's visible intermediate reasoning steps. Under H-CoT, refusal rates drop from 98% to below 2%. [arXiv:2502.12893](https://arxiv.org/abs/2502.12893)
- **DeepSeek-R1 Safety Assessment** — R1's baseline refusal rate is ~20% on harmful queries. Design flaw: R1 produces harmful content in its reasoning trace before its safety moderator fires. [arXiv:2502.12659](https://arxiv.org/abs/2502.12659)

**Multimodal attacks:**

- **Adversarial Image Jailbreaks** — Adversarial perturbations on images reliably jailbreak vision-language models (LLaVA, MiniGPT-4, InstructBLIP) even when text-based safety training is intact. Transfers across model families. [arXiv:2306.13213](https://arxiv.org/abs/2306.13213)
- **DiffusionAttacker (multimodal)** — See above.
- **PoisonedEye** — Embeds malicious instructions inside images in RAG-indexed documents. Triggered when a vision-capable agent retrieves and processes the image. [openreview.net](https://openreview.net/forum?id=6SIymOqJlc)

**2026 jailbreak research:**

- **Mastermind (Jan 2026)** — Hierarchical planning framework that decouples high-level attack objectives from tactical execution, guided by a knowledge repository that autonomously refines effective attack patterns. Achieves 94% ASR on DeepSeek V3, 93% on GPT-4o, 90% on o3-mini, 89% on DeepSeek-R1. [arXiv:2601.05445](https://arxiv.org/abs/2601.05445)
- **RACE — Reasoning-Augmented Conversation (Feb 2026)** — Reformulates harmful queries into benign reasoning tasks that lead models to produce harmful content. Up to 96% overall ASR, 82% on o1, 92% on DeepSeek-R1. [arXiv:2502.11054](https://arxiv.org/html/2502.11054v2)
- **UltraBreak (Feb 2026)** — Universal adversarial patterns for vision-language models that transfer across diverse jailbreak objectives and model families. [arXiv:2602.01025](https://arxiv.org/abs/2602.01025)
- **Reasoning Models as Autonomous Jailbreak Agents (Nature Communications 2026)** — When DeepSeek-R1, Gemini 2.5 Flash, Grok 3 Mini, and Qwen3 235B are used as autonomous jailbreak agents against nine target models, overall attack success rate reaches 97.14%. Converts jailbreaking from an expert activity into a non-expert-accessible automated process. [nature.com](https://www.nature.com/articles/s41467-026-69010-1)

**Fine-tuning as jailbreak:**

- Standard fine-tuning on completely benign data degrades alignment. Adversarial fine-tuning with 10 examples costs <$0.20 and strips GPT-3.5's safety guardrails. [arXiv:2310.03693](https://arxiv.org/abs/2310.03693)

**LLM-as-a-Judge exploitation:**

- Universal adversarial phrases appended to responses manipulate LLM judges into predicting inflated scores. Critical for red team pipelines that use automated evaluation. [arXiv:2402.14016](https://arxiv.org/abs/2402.14016)
- System-prompt injection into evaluation pipelines achieves higher success rates than content-layer attacks. [arXiv:2504.18333](https://arxiv.org/abs/2504.18333)

---

### Agentic & Multi-Agent Attacks

AI agents that use tools, browse the web, execute code, and persist across sessions dramatically expand the attack surface beyond single-turn LLM interactions.

**Memory poisoning:**

- **AgentPoison** — Backdoor attack targeting RAG-based agents. Optimizes triggers in embedding space so poisoned memory entries are retrieved with >80% probability whenever a trigger appears. No model retraining required. NeurIPS 2024. [arXiv:2407.12784](https://arxiv.org/abs/2407.12784)
- **MemoryGraft** — Injects malicious "successful task completion" records into an agent's memory. On future semantically similar tasks, the agent adopts the malicious procedure without any explicit trigger. Persistent cross-session compromise. [arXiv:2512.16962](https://arxiv.org/abs/2512.16962)
- **MINJA** — Query-only memory injection achieving >95% success rates via bridging steps and progressive shortening. No privileged access required — exploitable via normal user interactions. [arXiv:2503.03704](https://arxiv.org/abs/2503.03704)

**Control flow & privilege escalation:**

- **Multi-Agent Control-Flow Hijacking** — Compromised subagents re-route task execution to parent orchestrators, achieving access equivalent to the compromised agent: credentials, emails, calendars, files. 97% code execution rates observed. [arXiv:2510.17276](https://arxiv.org/abs/2510.17276)
- **ConfusedPilot** — Data corruption and leakage by exploiting Microsoft 365 Copilot's RAG context injection. UT Austin, DEF CON 32. [arXiv:2408.04870](https://arxiv.org/abs/2408.04870)

**MCP (Model Context Protocol) attacks:**

- **Tool Poisoning** — Malicious MCP server embeds prompt injection payloads inside tool descriptions or server instructions, poisoning the agent's context before the user's first interaction ("line jumping"). [Invariant Labs research](https://invariantlabs.ai/research)
- **CVE-2025-6514** — mcp-remote arbitrary command execution via malicious server URL. CVSS 9.6. [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2025-6514)
- **MCPTox** — Benchmark for tool poisoning attacks against real MCP servers. [arXiv:2508.14925](https://arxiv.org/abs/2508.14925)
- **MCP Registry Supply Chain** — Malicious servers registered in public MCP registries, impersonating legitimate tools. [vulnerablemcp.info](https://vulnerablemcp.info/)
- **MCP Rug Pull / Tool Shadowing** — MCP servers can silently modify tool definitions between sessions post-approval. A tool approved on Day 1 may be replaced by a malicious version by Day 7, exploiting cached user trust. Formally documented by Unit 42. [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)

**Self-replicating attacks:**

- **Morris II (AI Worm)** — First self-replicating worm targeting GenAI ecosystems. Adversarial self-replicating prompts cascade through RAG-based multi-agent pipelines without user interaction. Demonstrated against ChatGPT-4, Gemini Pro, and LLaVA in an email assistant simulation. [arXiv:2403.02817](https://arxiv.org/abs/2403.02817)

**Computer-use agent attacks:**

- Agents that control a desktop or browser (Anthropic Computer Use, OpenAI Operator) introduce a novel attack surface: malicious content on a rendered webpage can inject instructions via the visual/UI channel, bypassing text-based filters. [arXiv:2501.04219](https://arxiv.org/abs/2501.04219)

**2026 agentic attack research:**

- **MCP-ITP (Jan 2026)** — First automated framework for implicit tool poisoning in MCP. Formulates poisoned tool generation as black-box optimization. Achieves 84.2% attack success rate while suppressing detection to 0.3%. Existing safety alignment largely ineffective. [arXiv:2601.07395](https://arxiv.org/abs/2601.07395)
- **Viral Agent Loop (Feb 2026)** — Agents acting as vectors for self-propagating generative worms. Systematizes agentic runtime supply chain attacks: data supply chain (context injection + memory poisoning) and tool supply chain (discovery, implementation, invocation). [arXiv:2602.19555](https://arxiv.org/abs/2602.19555)
- **Sleeper Cell backdoor (Mar 2026)** — Novel stealthy backdoor for tool-using agents via SFT-then-GRPO fine-tuning. With 1,000 samples, trains models that are operationally deceptive while maintaining near-perfect stealth on utility benchmarks. [arXiv:2603.03371](https://arxiv.org/html/2603.03371v1)
- **ToxicSkills agent skills supply chain (Feb 2026)** — 36% of ClawHub agent skills contain prompt injection; 76 confirmed malicious payloads. 91% of malicious skills simultaneously use prompt injection alongside malicious code. Three lines of markdown sufficient to exfiltrate SSH keys. [snyk.io](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)
- **CVE-2026-0628 — Gemini Chrome panel hijacking (Jan 2026)** — Chrome WebView insufficient policy enforcement allows a low-privilege extension to inject code into Gemini Live's side panel and inherit file access, screenshot, and camera/microphone capabilities. CVSS 8.8. [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/gemini-live-in-chrome-hijacking/)
- **Claude Code CVEs (2025–2026)** — CVE-2025-59536: RCE via malicious Hook commands in `.claude/settings.json`, triggering automatically when an untrusted repository is opened. CVE-2026-21852: API key exfiltration by overriding `ANTHROPIC_BASE_URL` to an attacker endpoint — every Claude API call then sends the authorization header to the attacker. CVE-2026-31862: Critical command injection in Cloud CLI (CVSS 9.1). [research.checkpoint.com](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- **SesameOp — AI API as C2** — First confirmed real-world backdoor using a commercial AI API (OpenAI Assistants) as covert command-and-control. Threat actor was present for months before discovery. Now documented as MITRE ATLAS case study AML.CS0042. [microsoft.com/security/blog](https://www.microsoft.com/en-us/security/blog/2025/11/03/sesameop-novel-backdoor-uses-openai-assistants-api-for-command-and-control/)

---

### Training Data & Privacy Attacks

**Training data extraction:**

- **Carlini et al. (2021)** — LLMs memorize and reproduce verbatim training data including PII. Baseline methodology for extraction. [arXiv:2012.07805](https://arxiv.org/abs/2012.07805)
- **Divergence Attack (2023)** — Causes ChatGPT to emit memorized training data at 150× the normal rate. Demonstrates gigabyte-scale extraction from production LLMs. [arXiv:2311.17035](https://arxiv.org/abs/2311.17035)
- **Copyrighted Book Extraction (2025)** — Gemini 2.5 Pro and Grok 3 directly comply with instructions to extract memorized copyrighted book text. Claude 3.7 and GPT-4.1 require jailbreaking. [arXiv:2601.02671](https://arxiv.org/abs/2601.02671)
- **Diffusion model extraction** — Over 1,000 training images (including personal photos) recovered from diffusion models. [arXiv:2301.13188](https://arxiv.org/abs/2301.13188)

**Membership inference attacks (MIAs):**

- Determine whether a specific data point was in a model's training set. Directly relevant to GDPR, HIPAA, and data deletion compliance. Foundational paper: [arXiv:1610.05820](https://arxiv.org/abs/1610.05820)
- Critical evaluation (2024): most published LLM MIAs are methodologically flawed — performance near random chance under rigorous conditions. [arXiv:2402.07841](https://arxiv.org/abs/2402.07841) / SaTML 2025: [arXiv:2406.17975](https://arxiv.org/abs/2406.17975)
- **Tokenizer MIA** — Novel attack surface: tokenizers trained on pretraining-representative data leak membership. [arXiv:2510.05699](https://arxiv.org/abs/2510.05699)

**Model stealing:**

- **Carlini et al. (2024)** — Extracts the embedding projection layer from production LLMs. Cost: <$20 for GPT Ada/Babbage; <$2,000 for GPT-3.5-turbo's full projection matrix. [arXiv:2403.06634](https://arxiv.org/abs/2403.06634)
- **Logit-based extraction** — Most LLMs output logits restricted to a low-dimensional subspace, leaking non-public architecture information via API. Under $1,000 in queries. [arXiv:2403.09539](https://arxiv.org/abs/2403.09539)

**Embedding inversion:**

- Reconstruct original text inputs from embedding vectors with high fidelity using only a surrogate model (no access to the target model). Realistic threat to vector database deployments. ACL 2024. [arXiv:2406.10280](https://arxiv.org/abs/2406.10280)

**Federated learning gradient attacks:**

- **Deep Leakage from Gradients** — Shared gradients in federated learning can reconstruct original training inputs with high fidelity. NeurIPS 2019. [arXiv:1906.08935](https://arxiv.org/abs/1906.08935)
- **Inverting Gradients** — Extends reconstruction to large batch sizes and high-resolution images, making the attack practical at scale. Achieves quality sufficient to read text in images and identify individuals. NeurIPS 2020. [arXiv:2003.14053](https://arxiv.org/abs/2003.14053)

---

### Adversarial ML — Classical Models

| Attack Class | What It Does | Key Techniques |
|-------------|-------------|----------------|
| **Evasion** | Crafting inputs at test-time that fool a deployed model. Pixel perturbations that change classification, text perturbations that evade NLP classifiers. | FGSM, PGD, Carlini-Wagner (C&W), DeepFool |
| **Poisoning** | Corrupting training data so the trained model behaves maliciously. Affects integrity of models trained on scraped web data. | Clean-label poisoning, backdoor poisoning, gradient manipulation |
| **Backdoor / Trojan** | Model behaves correctly on clean inputs but triggers maliciously on a specific pattern. Supply chain threat when using third-party models. | BadNets, TrojAI, Physical triggers |
| **Model Inversion** | Reconstruct training inputs from model outputs. Threat to private training data. | Gradient-based inversion, generative inversion |

**Web-scale poisoning** — Controlling a small fraction of web content (common crawl, Wikipedia edits) is sufficient to influence model behavior. Carlini et al., 2023: [arXiv:2302.10149](https://arxiv.org/abs/2302.10149)

**LeftoverLocals (GPU Side-Channel, Trail of Bits, 2024)** — Cross-process recovery of LLM inference outputs from GPU local memory. An attacker with local GPU access can read partial KV-cache or logits from another process's LLM inference. Demonstrated against Apple, AMD, and Qualcomm GPUs. CVE-2023-4969. [Blog post](https://blog.trailofbits.com/2024/01/16/leftoverlocals-listening-to-llm-responses-through-leaked-gpu-local-memory/)

---

### Supply Chain & Model Poisoning

**Backdoor persistence through safety training:**

- **Sleeper Agents (Anthropic, 2024)** — Backdoor behaviors survive RLHF, supervised fine-tuning, and adversarial training. A model trained to insert malicious code when the year is 2024 (but write safe code otherwise) cannot be reliably cleaned. Adversarial training may make backdoors better hidden, not smaller. [arXiv:2401.05566](https://arxiv.org/abs/2401.05566)

**Code completion backdoors:**

- **CodeBreaker (USENIX Security 2024)** — LLM-assisted backdoor attack on code completion models that evades static analysis. Poisoned completions insert CWE-level vulnerabilities that are syntactically valid and bypass Semgrep/CodeQL. [arXiv:2406.06822](https://arxiv.org/abs/2406.06822)

**Malicious models on Hugging Face:**

- Two PyTorch models discovered (2025) using 7z compression (not ZIP) to evade Picklescan, hiding malicious payloads in ML model files. GGUF format has no production-ready security scanner as of early 2026.
- **PickleBall (CCS 2025)** — ~44.9% of Hugging Face repos contain pickle-format models. Proposes a secure deserialization sandbox. [arXiv:2508.15987](https://arxiv.org/abs/2508.15987)

**Watermark attacks:**

- Watermark-removal via semantic paraphrase and watermark-spoofing (injecting a target watermark into malicious content) work against major LLM watermarking schemes. [arXiv:2402.16187](https://arxiv.org/abs/2402.16187)
- Adaptive attackers with GPU access achieve >96% watermark evasion in under 7 hours. [arXiv:2410.02440](https://arxiv.org/abs/2410.02440)

**2026 supply chain:**

- **LiteLLM TeamPCP supply chain attack (Mar 2026)** — Threat actor stole PyPI credentials via a compromised Trivy GitHub Action in LiteLLM's CI/CD pipeline. Published backdoored versions 1.82.7 and 1.82.8 with multi-stage credential stealers. With 3.4 million daily downloads, packages were live for ~3 hours. Tracked by Wiz, Sonatype, and Datadog Security Labs. [wiz.io/blog](https://www.wiz.io/blog/threes-a-crowd-teampcp-trojanizes-litellm-in-continuation-of-campaign)
- **MCP ecosystem CVEs — 30 CVEs in 60 days (2026)** — First 60 days of 2026 saw 30+ CVEs across MCP servers, clients, and infrastructure. Root causes: missing input validation (43% exec/shell injection), absent authentication, blind trust in tool descriptions. [vulnerablemcp.info](https://vulnerablemcp.info/)

**RAG poisoning:**

- **PoisonedRAG** — Injecting 5 malicious texts into a database of millions induces target answers. Success rates: 97% (NQ), 99% (HotpotQA), 91% (MS-MARCO) against PaLM 2. USENIX Security 2025. [arXiv:2402.07867](https://arxiv.org/abs/2402.07867)
- **Phantom RAG** — Dormant malicious document that remains inactive during normal queries, activating only when specific trigger keywords appear. Significantly harder to detect than always-active poisoned documents. [arXiv:2405.20485](https://arxiv.org/abs/2405.20485)
- **Semantic Chameleon** — Gradient-guided corpus-dependent RAG poisoning. Achieves 38% co-retrieval on pure vector retrieval; notably, hybrid BM25+vector retrieval reduces attack success from 38% to 0%, making retrieval strategy a key defensive decision. [arXiv:2603.18034](https://arxiv.org/abs/2603.18034)
- **AgentPoison** — Embedding-space backdoor targeting RAG agents (see [Agentic Attacks](#agentic--multi-agent-attacks)).

---

### AI Infrastructure Attacks

These target the MLOps stack — training clusters, model serving, notebook environments, and cloud AI platforms — rather than the model itself.

| Attack | Target | Details |
|--------|--------|---------|
| **MLflow / Ray / Kubeflow CVEs** | ML pipeline orchestration | Unauthenticated RCE, deserialization, SSRF. Tracked at [ProtectAI Sightline](https://sightline.protectai.com/) |
| **Langflow RCE ([CVE-2025-3248](https://nvd.nist.gov/vuln/detail/CVE-2025-3248))** | Agentic workflow builder | Unauthenticated RCE in Langflow via code execution endpoint. CVSS 9.8 |
| **Langflow RCE (CVE-2026-33017)** | Agentic workflow builder | New critical RCE (CVSS 9.3) in Langflow ≤1.8.1. Exploited in the wild within 20 hours of disclosure — attackers built working exploits from the advisory alone, no PoC needed. [thehackernews.com](https://thehackernews.com/2026/03/critical-langflow-flaw-cve-2026-33017.html) |
| **Hugging Face cross-tenant (Wiz, BH 2024)** | AI cloud platforms | Cross-tenant attacks on Hugging Face Spaces, Replicate, SAP AI Core. Demonstrated at Black Hat USA 2024. [Wiz Research](https://www.wiz.io/blog/sapwned-sap-ai-vulnerabilities-ai-security) |
| **NVIDIAScape ([CVE-2025-23266](https://nvd.nist.gov/vuln/detail/CVE-2025-23266))** | GPU container infrastructure | Container escape via NVIDIA GPU driver. CVSS 9.0. Covered at Black Hat USA 2025. |
| **[CVE-2024-0132](https://nvd.nist.gov/vuln/detail/CVE-2024-0132)** | NVIDIA Container Toolkit | Container escape affecting shared GPU cloud environments. |
| **[CVE-2026-26118](https://nvd.nist.gov/vuln/detail/CVE-2026-26118)** | Azure MCP Server | SSRF-based elevation of privilege. Allows authorized attacker to escalate privileges via crafted input to MCP server tools. March 2026 Patch Tuesday. |
| **[CVE-2026-27825](https://nvd.nist.gov/vuln/detail/CVE-2026-27825)** | mcp-atlassian | Critical unauthenticated RCE and SSRF via path traversal in Confluence attachment download tools. Missing directory confinement enables arbitrary file write and local privilege escalation. |
| **[CVE-2026-23744](https://nvd.nist.gov/vuln/detail/CVE-2026-23744)** | MCPJam Inspector ≤1.4.2 | RCE via crafted HTTP request triggering MCP server installation. Server listens on 0.0.0.0 by default, enabling remote exploitation. |
| **CVE-2026-22778 — vLLM RCE** | vLLM inference server (versions 0.8.3–0.14.0) | CVSS 9.8. Two-stage exploit: PIL error leak exposes heap address (ASLR bypass), then JPEG2000 decoder heap overflow via OpenCV triggers RCE via a malicious video URL. No authentication required. Patched in 0.14.1. [orca.security](https://orca.security/resources/blog/cve-2026-22778-vllm-rce-vulnerability/) |
| **n8n CVE-2026-21858 "Ni8mare"** | n8n AI workflow platform | CVSS 10.0. Content-Type confusion in webhook/file-handling allows unauthenticated full system compromise. When n8n has LLM chatbot nodes, an attacker can exfiltrate files through the AI chat interface. Affects < 1.121.0. [thehackernews.com](https://thehackernews.com/2026/01/critical-n8n-vulnerability-cvss-100.html) |
| **Jupyter/vger** | MLOps notebooks | Authenticated Jupyter instances: enumerate kernels, execute arbitrary code, exfiltrate training data. [vger tool](https://github.com/JosephTLucas/vger) |

**AI coding assistant attacks:**

- **IDEsaster** — Systematic disclosure of 24+ CVEs affecting Cursor, Windsurf, GitHub Copilot, Zed, Kiro.dev, Cline, and others. Attack chain: Prompt Injection → AI tool use → base IDE features (RCE, credential exfiltration). 100% of tested AI IDEs were vulnerable. [arXiv:2601.17548](https://arxiv.org/abs/2601.17548)
- **Rules File Backdoor** — Hidden Unicode characters in `.cursorrules` / Copilot configuration files silently poison AI-generated code with backdoors that survive code review. A supply chain attack requiring no runtime access. [pillar.security](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- **AI-generated code CVEs (2026 trend)** — AI vibe-coded code has a ~45% security failure rate despite 95%+ syntax correctness. 35 CVEs from AI-generated code disclosed in March 2026 alone (up from 6 in January). 86% vulnerable to XSS; 88% to log injection. Tracked by Georgia Tech "Vibe Security Radar." [infosecurity-magazine.com](https://www.infosecurity-magazine.com/news/ai-generated-code-vulnerabilities/)

**Real-world exploits:** [ProtectAI AI-Exploits](https://github.com/protectai/ai-exploits) — working PoC exploits for disclosed CVEs in MLflow, Ray, Hugging Face, and other MLOps infrastructure.

---

### Offensive Use of AI

**Autonomous vulnerability exploitation:**

- **GPT-4 one-day CVE exploitation** — GPT-4 agents autonomously exploit 87% of one-day CVEs given CVE descriptions. GPT-3.5, open-source LLMs, and Metasploit scored 0%. [arXiv:2404.08144](https://arxiv.org/abs/2404.08144)
- **Multi-agent zero-day exploitation** — Hierarchical LLM teams achieve 42% success on novel, undisclosed vulnerabilities. [arXiv:2406.01637](https://arxiv.org/abs/2406.01637)
- **CVE-Genie** — Automates CVE-to-exploit reproduction using multi-agent LLMs. Reproduces ~51% of 2024–2025 CVEs at ~$2.77 per CVE. [arXiv:2509.01835](https://arxiv.org/abs/2509.01835)

**Google Project Zero — Big Sleep:**

- Project Naptime → Big Sleep: a Google DeepMind + Project Zero framework providing AI agents with Code Browser, Python execution, and Debugger tools for autonomous vulnerability research. Discovered a real-world exploitable stack buffer underflow in SQLite — the first publicly documented AI-discovered real-world zero-day. Fixed the same day.
- [Project Naptime (June 2024)](https://projectzero.google/2024/06/project-naptime.html)
- [From Naptime to Big Sleep (October 2024)](https://projectzero.google/2024/10/from-naptime-to-big-sleep.html)

**AI in active threat operations:**

- OpenAI disrupted 40+ threat actor networks since 2024 using its models for phishing, influence operations, and SIGINT-style monitoring tool development. [openai.com](https://openai.com/global-affairs/disrupting-malicious-uses-of-ai-october-2025/)
- Documented cases: AI-generated SVG phishing payloads with obfuscated malicious code; AI-generated spear-phishing with 38% click rates; Dark LLM vendors offering uncensored 80B+ models at $30–$200/month. (Group-IB, 2025)
- **GTG-2002 threat actor** — Claude Code weaponized to conduct automated attacks against 17+ organizations (2025). [anthropic.com](https://www-cdn.anthropic.com/b2a76c6f6992465c09a6f2fce282f6c0cea8c200.pdf)
- **AI accelerating attack lifecycles (Unit 42, Feb 2026)** — Based on 750+ high-stakes incidents, AI accelerated attack lifecycles 4× over the prior year. Fastest cases: initial access to data exfiltration in 72 minutes. [paloaltonetworks.com](https://www.paloaltonetworks.com/blog/2026/02/unit-42-global-ir-report/)
- **CrowdStrike 2026 Global Threat Report** — Average eCrime breakout time fell to 29 minutes; fastest observed: 27 seconds. AI-enabled attacks up 89% YoY. 24 new adversaries named; 281+ total tracked. Adversaries actively injecting malicious prompts into GenAI tools at 90+ organizations. [crowdstrike.com](https://www.crowdstrike.com/en-us/blog/crowdstrike-2026-global-threat-report-findings/)
- **IBM X-Force Threat Intelligence Index 2026** — 44% increase in public-facing application exploitation; AI-enabled attacks documented across vulnerability discovery, spear-phishing generation, and data synthesis for targeting. [ibm.com/security/blog](https://newsroom.ibm.com/2026-02-25-ibm-2026-x-force-threat-index-ai-driven-attacks-are-escalating-as-basic-security-gaps-leave-enterprises-exposed)
- **Google GTIG AI Threat Tracker** — DPRK, Iran, China, and Russia all operationalized AI in 2025. PROMPTFLUX and PROMPTSTEAL are first documented AI-native malware families using LLMs at execution time. 100,000+ model extraction attempts observed and mitigated. State-backed actors using Gemini for OSINT synthesis and target profiling. [cloud.google.com](https://cloud.google.com/blog/topics/threat-intelligence/distillation-experimentation-integration-ai-adversarial-use)
- **Microsoft "AI as Tradecraft" (Mar 2026)** — Detailed analysis of threat actor AI use across the full attack lifecycle: reconnaissance, spear-phishing, malware generation, evasion, and post-exploitation iteration. Documents emerging agentic AI tradecraft. [microsoft.com/security/blog](https://www.microsoft.com/en-us/security/blog/2026/03/06/ai-as-tradecraft-how-threat-actors-operationalize-ai/)
- **HiddenLayer 2026 AI Threat Landscape Report** — 1 in 8 reported AI breaches now linked to agentic systems; 35% of AI-related breaches sourced from malware in public model/code repositories; 31% of orgs don't know if they experienced an AI security breach. [hiddenlayer.com](https://www.hiddenlayer.com/news/hiddenlayer-releases-the-2026-ai-threat-landscape-report-spotlighting-the-rise-of-agentic-ai-and-the-expanding-attack-surface-of-autonomous-systems)
- **CrowdStrike 2026 Global Threat Report** — FANCY BEAR deployed LLM-enabled malware (LAMEHUG) for automated recon; FAMOUS CHOLLIMA (DPRK) scaled insider operations using AI-generated personas; average eCrime breakout time fell to 29 minutes (fastest: 27 seconds); AI-enabled attacks up 89% YoY. [crowdstrike.com](https://www.crowdstrike.com/en-us/press-releases/2026-crowdstrike-global-threat-report/)
- **LLMjacking — Operation Bizarre Bazaar (Jan 2026)** — First large-scale LLMjacking campaign with full commercial monetization. 35,000 attack sessions targeting exposed Ollama instances, OpenAI-compatible APIs, and MCP servers. Stolen LLM access resold at 40–60% discount on silver.inc marketplace. [pillar.security](https://www.pillar.security/blog/operation-bizarre-bazaar-first-attributed-llmjacking-campaign-with-commercial-marketplace-monetization)
- **91,000+ sessions targeting LLM infrastructure (GreyNoise, Feb 2026)** — GreyNoise sensors observed 91,403 sessions targeting Ollama inference servers from Oct 2025 to Jan 2026. A single 11-day campaign tested 73+ model endpoints across GPT-4o, Claude, Llama, Gemini, Mistral, DeepSeek-R1. [greynoise.io](https://www.greynoise.io/blog/threat-actors-actively-targeting-llms)
- **CyberExplorer benchmark (Feb 2026)** — AI agents evaluated autonomously performing recon, target selection, and exploitation against 40 real-world CTF-derived web services. [arXiv:2602.08023](https://arxiv.org/html/2602.08023v1)
- **Wiz AI Cyber Model Arena (Feb 2026)** — 257 real-world challenges (zero-day discovery, CVE exploitation, cloud security). AI agents solved 9 of 10 web challenges; no single model dominates all domains. [wiz.io/blog](https://www.wiz.io/blog/introducing-ai-cyber-model-arena-a-real-world-benchmark-for-ai-agents-in-cybersec)

---

### Attack Tutorials & Walkthroughs

Hands-on resources with working code and step-by-step attack execution — not just theory.

**Prompt injection:**

| Resource | Author | What It Covers |
|----------|--------|----------------|
| [Embrace The Red — Prompt Injection Series](https://embracethered.com/blog/tags/prompt-injection/) | Johann Rehberger | The most comprehensive practitioner blog for real-world prompt injection exploitation. Every post is a step-by-step write-up against a production system (Claude Computer Use, GitHub Copilot, ChatGPT Operator, Microsoft Copilot). Exact payloads, attack chains, screenshots, and impact analysis throughout. |
| [ZombAIs: From Prompt Injection to C2 with Claude Computer Use](https://embracethered.com/blog/posts/2024/claude-computer-use-c2-the-zombais-are-coming/) | Johann Rehberger | End-to-end walkthrough: indirect prompt injection → malware download → C2 via Sliver. Shows exact HTML payload, the bash commands Claude executes, and Sliver C2 setup. |
| [Data Exfiltration from Slack AI via Indirect Prompt Injection](https://www.promptarmor.com/resources/data-exfiltration-from-slack-ai-via-indirect-prompt-injection) | PromptArmor | Step-by-step attack chain: attacker plants malicious instruction in a Slack channel → victim queries Slack AI → private API key exfiltrated via crafted markdown link. Full payload and exfiltration mechanism shown. |
| [LearnPrompting — Prompt Hacking: Offensive Measures](https://learnprompting.org/docs/prompt_hacking/offensive_measures/introduction) | LearnPrompting.org | 20 documented delivery techniques with worked examples: payload splitting, token smuggling, recursive injection, code injection, indirect injection, virtualization, alignment hacking. Each technique has its own page with concrete payloads. |
| [AI Red Teaming Playground Labs — PyRIT Walkthrough](https://breakpoint-labs.com/ai-red-teaming-playground-labs-setup-and-challenge-1-walkthrough-with-pyrit/) | BreakPoint Labs | Sets up Microsoft's AI Red Teaming Playground and walks through credential exfiltration (Challenge 1) and metaprompt extraction via Base64 obfuscation (Challenge 2) using PyRIT — both manually and automated with code. |

**Jailbreaking:**

| Resource | Author | What It Covers |
|----------|--------|----------------|
| [PAIR Official Implementation](https://github.com/patrickrchao/JailbreakingLLMs) | Chao et al. | Full Python implementation of the PAIR jailbreak algorithm: an attacker LLM iteratively refines prompts against a target LLM until it complies. Supports OpenAI, Anthropic, and Google models. Runnable CLI with `--attack-model`, `--target-model`, `--judge-model` flags. Achieves jailbreaks in ~20 queries. |
| [AutoDAN Official Implementation](https://github.com/SheltonLiu-N/AutoDAN) | Liu et al. (ICLR 2024) | Hierarchical genetic algorithm generating fluent, stealthy jailbreak prompts that pass perplexity-based filters that block GCG suffixes. Supports Llama-2, Vicuna, GPT-3.5, GPT-4. Full training and evaluation pipeline. |
| [Applying Garak to LLMs — Step-by-Step](https://www.databricks.com/blog/ai-security-action-applying-nvidias-garak-llms-databricks) | Databricks / NVIDIA | Practical walkthrough of running NVIDIA Garak against hosted LLMs: probe configuration, scan execution, and reading the HTML vulnerability report. Covers 120+ vulnerability categories including prompt injection, jailbreaks, and toxic output. |

**Agentic & MCP attacks:**

| Resource | Author | What It Covers |
|----------|--------|----------------|
| [MCP Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | Invariant Labs | Direct tool poisoning (hidden instructions in tool descriptions exfiltrate SSH keys and mcp.json), shadow attacks (hijack a trusted tool from a separate server), and sleeper rug pull. Verbatim Python MCP server code shown for each attack. |
| [Hijacking Multi-Agent Systems](https://blog.trailofbits.com/2025/07/31/hijacking-multi-agent-systems-in-your-pajamas/) | Trail of Bits | Privilege escalation in multi-agent systems: demonstrates how high-privilege agents trust unvalidated output from low-privilege subagents. Covers the ANSI escape sequence (line jumping) attack vector for MCP in detail. |
| [AgentDojo — Agent Prompt Injection](https://github.com/ethz-spylab/agentdojo) | ETH Zurich (NeurIPS 2024) | Runnable benchmark for injecting attacks against LLM agents across 5 domains (workspace, banking, travel, Slack). CLI with attack/defense flags; 40+ injection tasks tested against Claude 3.5 Sonnet and GPT-4o. |

**RAG poisoning:**

| Resource | Author | What It Covers |
|----------|--------|----------------|
| [PoisonedRAG — Official Repo](https://github.com/sleeepeer/PoisonedRAG) | Zou et al. (USENIX Security 2025) | End-to-end poisoned RAG pipeline. Injects a small number of adversarial texts into a vector database and drives the LLM to output attacker-controlled answers. 97% attack success rate (black-box). Reproduces NQ, HotpotQA, and MS-MARCO experiments. |
| [RAG Poisoning: All You Need is One Document](https://labs.zenity.io/p/rag-poisoning-need-one-document) | Zenity Labs | Enterprise-focused walkthrough showing how a single injected document poisons a RAG-based corporate assistant. Covers realistic attack scenarios against internal enterprise AI deployments. |

**Adversarial ML:**

| Resource | Author | What It Covers |
|----------|--------|----------------|
| [Machine Learning Attack Series — Husky AI](https://embracethered.com/blog/posts/2020/machine-learning-attack-series-overview/) | Johann Rehberger | 20-part series attacking a real image classifier end-to-end: FGSM perturbations, model stealing, backdooring, image scaling attacks, GAN-based evasion, pickle backdoors, and Jupyter notebook exploitation. Uses ART and Microsoft Counterfit. Companion code: [wunderwuzzi23/huskyai](https://github.com/wunderwuzzi23/huskyai). |
| [FGSM Tutorial (PyTorch)](https://docs.pytorch.org/tutorials/beginner/fgsm_tutorial.html) | PyTorch | Step-by-step FGSM attack against MNIST: gradient computation, perturbation application, evasion rate measurement across epsilon values. The canonical runnable introduction to adversarial examples. |
| [Adversarial Robustness: Theory and Practice](https://adversarial-ml-tutorial.org/) | Kolter & Madry (NeurIPS 2018 Tutorial) | PGD attacks, adversarial training, and certified defenses — with downloadable Jupyter notebooks per chapter. Rigorous but approachable. |

**AI infrastructure exploitation:**

| Resource | Author | What It Covers |
|----------|--------|----------------|
| [Hacking AI: System Takeover via MLflow](https://protectai.com/blog/hacking-ai-system-takeover-exploit-in-mlflow) | Protect AI | Step-by-step exploitation of CVE-2023-1177 (MLflow LFI): enumerate credentials from cloud metadata endpoint, leverage MLflow artifact access for full system takeover. Companion code in [protectai/ai-exploits](https://github.com/protectai/ai-exploits). |

---

## 2. Key Research Papers

*All linked to free arXiv versions or official open-access pages. Organized by attack class.*

### Prompt Injection & Jailbreaking Papers

| Paper | Authors | Year | Conference / Venue | arXiv |
|-------|---------|------|--------------------|-------|
| **Jailbreaking Leaves a Trace: Detecting Attacks from Internal Representations** | Kadali et al. | 2026 | — | [2602.11495](https://arxiv.org/abs/2602.11495) |
| **Toward Universal and Transferable Jailbreak Attacks on VLMs (UltraBreak)** | Cui et al. | 2026 | — | [2602.01025](https://arxiv.org/abs/2602.01025) |
| **Jailbreaks on Vision Language Models via Multimodal Reasoning** | Noheria & Yao | 2026 | — | [2601.22398](https://arxiv.org/abs/2601.22398) |
| **Prompt Injection Attacks on Agentic Coding Assistants (SoK)** | Maloyan & Namiot | 2026 | — | [2601.17548](https://arxiv.org/abs/2601.17548) |
| **MCP-ITP: Automated Framework for Implicit Tool Poisoning in MCP** | Li et al. | 2026 | — | [2601.07395](https://arxiv.org/abs/2601.07395) |
| **iMIST: Jailbreaking via Iterative Tool-Disguised Attacks using Reinforcement Learning** | Wang et al. | 2026 | — | [2601.05466](https://arxiv.org/abs/2601.05466) |
| **Knowledge-Driven Multi-Turn Jailbreaking on LLMs (Mastermind)** | Li et al. | 2026 | — | [2601.05445](https://arxiv.org/abs/2601.05445) |
| **When AI Meets the Web: Prompt Injection Risks in Third-Party AI Chatbot Plugins** | Kaya et al. | 2025 | IEEE S&P 2026 | [2511.05797](https://arxiv.org/abs/2511.05797) |
| **H-CoT: Hijacking Chain-of-Thought Safety Reasoning to Jailbreak Large Reasoning Models** | Kuo et al. | 2025 | — | [2502.12893](https://arxiv.org/abs/2502.12893) |
| **The Hidden Risks of Large Reasoning Models: A Safety Assessment of R1** | Zhou et al. | 2025 | — | [2502.12659](https://arxiv.org/abs/2502.12659) |
| **DiffusionAttacker: Diffusion-Driven Prompt Manipulation for LLM Jailbreak** | Wang et al. | 2024 | EMNLP 2025 | [2412.17522](https://arxiv.org/abs/2412.17522) |
| **Great, Now Write an Article About That: The Crescendo Multi-Turn Jailbreak Attack** | Russinovich, Salem, Eldan (Microsoft) | 2024 | USENIX Security 2025 | [2404.01833](https://arxiv.org/abs/2404.01833) |
| **Is LLM-as-a-Judge Robust? Universal Adversarial Attacks on Zero-shot LLM Assessment** | Raina et al. | 2024 | EMNLP 2024 | [2402.14016](https://arxiv.org/abs/2402.14016) |
| **Many-Shot Jailbreaking** | Anil et al. (Anthropic) | 2024 | NeurIPS 2024 | [anthropic.com](https://www.anthropic.com/research/many-shot-jailbreaking) |
| **Formalizing and Benchmarking Prompt Injection Attacks and Defenses** | Liu et al. | 2024 | USENIX Security 2024 | [USENIX](https://www.usenix.org/conference/usenixsecurity24/presentation/liu-yupei) |
| **Jailbreaking Black Box Large Language Models in Twenty Queries (PAIR)** | Chao, Robey et al. | 2023 | NeurIPS 2024 | [2310.08419](https://arxiv.org/abs/2310.08419) |
| **Universal and Transferable Adversarial Attacks on Aligned Language Models (GCG)** | Zou, Wang, Carlini et al. | 2023 | — | [2307.15043](https://arxiv.org/abs/2307.15043) |
| **Visual Adversarial Examples Jailbreak Aligned Large Language Models** | Qi et al. | 2023 | AAAI 2024 | [2306.13213](https://arxiv.org/abs/2306.13213) |
| **Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection** | Greshake, Abdelnabi et al. | 2023 | IEEE S&P Workshop | [2302.12173](https://arxiv.org/abs/2302.12173) |
| **Red Teaming Language Models with Language Models** | Perez et al. (Google) | 2022 | — | [2202.03286](https://arxiv.org/abs/2202.03286) |

### Privacy & Extraction Papers

| Paper | Authors | Year | Conference / Venue | arXiv |
|-------|---------|------|--------------------|-------|
| **AttenMIA: Attention-Based Membership Inference Attack on LLMs** | Zaree et al. | 2026 | — | [2601.18110](https://arxiv.org/abs/2601.18110) |
| **Depth Gives a False Sense of Privacy: LLM Internal States Inversion** | Dong, Meng, Zhu et al. | 2025 | USENIX Security 2025 | [2507.16372](https://arxiv.org/abs/2507.16372) |
| **Exploring the Limits of Strong Membership Inference Attacks on Large Language Models** | Hayes, Shumailov et al. (Google DeepMind) | 2025 | — | [2505.18773](https://arxiv.org/abs/2505.18773) |
| **SoK: Membership Inference Attacks on LLMs are Rushing Nowhere (and How to Fix It)** | Meeus et al. | 2024 | IEEE SaTML 2025 | [2406.17975](https://arxiv.org/abs/2406.17975) |
| **Transferable Embedding Inversion Attack** | Huang et al. | 2024 | ACL 2024 | [2406.10280](https://arxiv.org/abs/2406.10280) |
| **Logits of API-Protected LLMs Leak Proprietary Information** | Finlayson et al. | 2024 | — | [2403.09539](https://arxiv.org/abs/2403.09539) |
| **Stealing Part of a Production Language Model** | Carlini et al. | 2024 | ICML 2024 | [2403.06634](https://arxiv.org/abs/2403.06634) |
| **Do Membership Inference Attacks Work on Large Language Models?** | Duan et al. | 2024 | COLM 2024 | [2402.07841](https://arxiv.org/abs/2402.07841) |
| **Scalable Extraction of Training Data from (Production) Language Models** | Nasr, Carlini et al. | 2023 | IEEE S&P 2024 | [2311.17035](https://arxiv.org/abs/2311.17035) |
| **Extracting Training Data from Diffusion Models** | Carlini, Hayes et al. | 2023 | USENIX Security 2023 | [2301.13188](https://arxiv.org/abs/2301.13188) |
| **Extracting Training Data from Large Language Models** | Carlini et al. | 2021 | USENIX Security 2021 | [2012.07805](https://arxiv.org/abs/2012.07805) |
| **Inverting Gradients — How Easy Is It to Break Privacy in Federated Learning?** | Geiping et al. | 2020 | NeurIPS 2020 | [2003.14053](https://arxiv.org/abs/2003.14053) |
| **Deep Leakage from Gradients** | Zhu et al. | 2019 | NeurIPS 2019 | [1906.08935](https://arxiv.org/abs/1906.08935) |
| **Membership Inference Attacks Against Machine Learning Models** | Shokri et al. | 2017 | IEEE S&P 2017 | [1610.05820](https://arxiv.org/abs/1610.05820) |
| **Stealing Machine Learning Models via Prediction APIs** | Tramèr et al. | 2016 | USENIX Security 2016 | [1609.02943](https://arxiv.org/abs/1609.02943) |

### Agent Security Papers

| Paper | Authors | Year | Conference / Venue | arXiv |
|-------|---------|------|--------------------|-------|
| **Sleeper Cell: Injecting Latent Malice Temporal Backdoors into Tool-Using LLMs** | Pallakonda et al. | 2026 | — | [2603.03371](https://arxiv.org/html/2603.03371v1) |
| **MM-MEPA: Stealth Poisoning Attacks on Multimodal RAG via Image Metadata** | Edemacu & Shokri | 2026 | — | [2603.00172](https://arxiv.org/abs/2603.00172) |
| **Agentic AI as a Cybersecurity Attack Surface: Runtime Supply Chain Threats** | Jiang et al. | 2026 | — | [2602.19555](https://arxiv.org/abs/2602.19555) |
| **Benchmarking Knowledge-Extraction Attacks on RAG** | Qi et al. | 2026 | — | [2602.09319](https://arxiv.org/abs/2602.09319) |
| **Overcoming the Retrieval Barrier: Indirect Prompt Injection in the Wild** | Chang, Bao et al. | 2026 | — | [2601.07072](https://arxiv.org/abs/2601.07072) |
| **Memory Poisoning Attack and Defense on Memory-Based LLM-Agents** | Sunil et al. | 2026 | — | [2601.05504](https://arxiv.org/abs/2601.05504) |
| **CorruptRAG: Practical Poisoning Attacks against RAG (single-document)** | Zhang et al. | 2026 | — | [2504.03957](https://arxiv.org/abs/2504.03957) |
| **TAMAS: Benchmarking Adversarial Risks in Multi-Agent LLM Systems** | Kavathekar et al. | 2025 | — | [2511.05269](https://arxiv.org/abs/2511.05269) |
| **Breaking and Fixing Defenses Against Control-Flow Hijacking in Multi-Agent Systems** | Jha et al. | 2025 | COLM 2025 | [2510.17276](https://arxiv.org/abs/2510.17276) |
| **EchoLeak (CVE-2025-32711): Zero-Click Microsoft Copilot Data Exfiltration** | Reddy & Gujral | 2025 | — | [2509.10540](https://arxiv.org/abs/2509.10540) |
| **MCPTox: A Benchmark for Tool Poisoning Attacks on Real-World MCP Servers** | Wang et al. | 2025 | — | [2508.14925](https://arxiv.org/abs/2508.14925) |
| **A Practical Memory Injection Attack against LLM Agents (MINJA)** | Dong et al. | 2025 | — | [2503.03704](https://arxiv.org/abs/2503.03704) |
| **Red-Teaming LLM Multi-Agent Systems via Communication Attacks (AiTM)** | He et al. | 2025 | ACL 2025 | [2502.14847](https://arxiv.org/abs/2502.14847) |
| **Agent Security Bench (ASB): Formalizing and Benchmarking Attacks and Defenses in LLM-based Agents** | Zhang et al. | 2024 | ICLR 2025 | [2410.02644](https://arxiv.org/abs/2410.02644) |
| **AgentPoison: Red-teaming LLM Agents via Poisoning Memory or Knowledge Bases** | Chen et al. | 2024 | NeurIPS 2024 | [2407.12784](https://arxiv.org/abs/2407.12784) |
| **Here Comes The AI Worm: Zero-click Worms Targeting GenAI-Powered Applications (Morris II)** | Cohen, Bitton, Ben Nassi | 2024 | — | [2403.02817](https://arxiv.org/abs/2403.02817) |
| **PoisonedRAG: Knowledge Corruption Attacks to Retrieval-Augmented Generation** | Zou et al. | 2024 | USENIX Security 2025 | [2402.07867](https://arxiv.org/abs/2402.07867) |

### Adversarial ML & Robustness Papers

| Paper | Authors | Year | Conference / Venue | arXiv |
|-------|---------|------|--------------------|-------|
| **Adversarially Robust CLIP Models Can Induce Better (Robust) Perceptual Metrics** | Croce et al. | 2025 | IEEE SaTML 2025 | [2502.11725](https://arxiv.org/abs/2502.11725) |
| **Revisiting Physical-World Adversarial Attack on Traffic Sign Recognition: A Commercial Systems Perspective** | Wang et al. | 2024 | NDSS 2025 | [2409.09860](https://arxiv.org/abs/2409.09860) |
| **Defending Against Unforeseen Failure Modes with Latent Adversarial Training** | Casper et al. | 2024 | — | [2403.05030](https://arxiv.org/abs/2403.05030) |
| **An Image Is Worth 1000 Lies: Adversarial Transferability across Prompts on Vision-Language Models (CroPA)** | Luo et al. | 2024 | ICLR 2024 | [2403.09766](https://arxiv.org/abs/2403.09766) |
| **Scaling Laws for Black Box Adversarial Attacks** | Liu et al. | 2024 | — | [2411.16782](https://arxiv.org/abs/2411.16782) |
| **Poisoning Web-Scale Training Datasets is Practical** | Carlini et al. | 2023 | IEEE S&P 2024 | [2302.10149](https://arxiv.org/abs/2302.10149) |
| **Radioactive Data: Tracing Through Training** | Sablayrolles et al. (FAIR) | 2020 | ICML 2020 | [2002.00937](https://arxiv.org/abs/2002.00937) |
| **Towards Deep Learning Models Resistant to Adversarial Attacks (PGD)** | Madry et al. | 2017 | ICLR 2018 | [1706.06083](https://arxiv.org/abs/1706.06083) |
| **Explaining and Harnessing Adversarial Examples (FGSM)** | Goodfellow, Shlens, Szegedy | 2015 | ICLR 2015 | [1412.6572](https://arxiv.org/abs/1412.6572) |

### Backdoors & Supply Chain Papers

| Paper | Authors | Year | Conference / Venue | arXiv |
|-------|---------|------|--------------------|-------|
| **Triggers Hijack Language Circuits: Mechanistic Analysis of Backdoor Behaviors in LLMs** | Lasnier et al. | 2026 | — | [2602.10382](https://arxiv.org/html/2602.10382) |
| **The Trigger in the Haystack: Extracting and Reconstructing LLM Backdoor Triggers** | Bullwinkel, Severi et al. (Microsoft) | 2026 | — | [2602.03085](https://arxiv.org/abs/2602.03085) |
| **Virus Infection Attack on LLMs: Your Poisoning Can Spread 'VIA' Synthetic Data** | Liang et al. | 2025 | NeurIPS 2025 Spotlight | [2509.23041](https://arxiv.org/abs/2509.23041) |
| **BackdoorLLM: A Comprehensive Benchmark for Backdoor Attacks on LLMs** | Li et al. | 2024 | NeurIPS 2025 | [2408.12798](https://arxiv.org/abs/2408.12798) |
| **CodeBreaker: LLM-Assisted Backdoor Attack on Code Completion Models** | Yan et al. | 2024 | USENIX Security 2024 | [2406.06822](https://arxiv.org/abs/2406.06822) |
| **Sleeper Agents: Training Deceptive LLMs that Persist Through Safety Training** | Hubinger et al. (Anthropic) | 2024 | — | [2401.05566](https://arxiv.org/abs/2401.05566) |
| **Fine-tuning Aligned Language Models Compromises Safety** | Yang et al. | 2023 | ICLR 2024 | [2310.03693](https://arxiv.org/abs/2310.03693) |
| **Targeted Backdoor Attacks on Deep Learning Systems Using Data Poisoning** | Chen et al. | 2017 | — | [1712.05526](https://arxiv.org/abs/1712.05526) |
| **BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain** | Gu et al. | 2017 | — | [1708.06733](https://arxiv.org/abs/1708.06733) |

### Offensive AI Papers

| Paper | Authors | Year | Conference / Venue | arXiv |
|-------|---------|------|--------------------|-------|
| **CyberExplorer: Benchmarking LLM Offensive Security Capabilities** | Rani et al. | 2026 | — | [2602.08023](https://arxiv.org/html/2602.08023v1) |
| **To Defend Against Cyber Attacks, We Must Teach AI Agents to Hack** | Zhuo et al. | 2026 | — | [2602.02595](https://arxiv.org/pdf/2602.02595) |
| **AI-Driven Cybersecurity Threats: A Survey of Emerging Attacks** | Erukude et al. | 2026 | — | [2601.03304](https://arxiv.org/pdf/2601.03304) |
| **Jailbreak-Zero: A Path to Pareto Optimal Red Teaming for Large Language Models** | Hu et al. | 2026 | NeurIPS 2025 workshop | [2601.03265](https://arxiv.org/abs/2601.03265) |
| **Lessons From Red Teaming 100 Generative AI Products** | Microsoft AI Red Team | 2025 | — | [2501.07238](https://arxiv.org/abs/2501.07238) |
| **SoK: On the Offensive Potential of AI** | 14 authors | 2025 | IEEE SaTML 2025 | [Project site](https://sok-offensive-ai.github.io/) |
| **Teams of LLM Agents can Exploit Zero-Day Vulnerabilities** | Fang et al. | 2024 | — | [2406.01637](https://arxiv.org/abs/2406.01637) |
| **LLM Agents can Autonomously Exploit One-day Vulnerabilities** | Fang et al. | 2024 | — | [2404.08144](https://arxiv.org/abs/2404.08144) |
| **PentestGPT: An LLM-empowered Automatic Penetration Testing Tool** | Deng et al. | 2024 | USENIX Security 2024 | [USENIX](https://www.usenix.org/conference/usenixsecurity24/presentation/deng) |

### Defense Papers

| Paper | Authors | Year | Conference / Venue | arXiv |
|-------|---------|------|--------------------|-------|
| **Addressing Corpus Knowledge Poisoning Attacks on RAG Using Sparse Attention** | Dekel et al. | 2026 | — | [2602.04711](https://arxiv.org/abs/2602.04711) |
| **Privacy-Preserving RAG with Distance-Preserving Encryption (ppRAG)** | Ye et al. | 2026 | — | [2601.12331](https://arxiv.org/html/2601.12331) |
| **Constitutional Classifiers++: Efficient Production-Grade Defenses against Universal Jailbreaks** | Cunningham et al. (Anthropic) | 2026 | — | [2601.04603](https://arxiv.org/abs/2601.04603) |
| **E²AT: Multimodal Jailbreak Defense via Dynamic Joint Optimization** | Lu et al. | 2026 | — | [2503.04833](https://arxiv.org/abs/2503.04833) |
| **Mitigating Indirect Prompt Injection via Instruction-Following Intent Analysis** | Kang et al. | 2025 | — | [2512.00966](https://arxiv.org/abs/2512.00966) |
| **Constitutional Classifiers: Defending against Universal Jailbreaks** | Sharma et al. (Anthropic) | 2025 | — | [2501.18837](https://arxiv.org/abs/2501.18837) |
| **StruQ: Defending Against Prompt Injection with Structured Queries** | Chen et al. | 2025 | USENIX Security 2025 | [2402.06363](https://arxiv.org/abs/2402.06363) |
| **Provably Robust Multi-bit Watermarking for AI-generated Text** | Qu et al. | 2025 | USENIX Security 2025 | [2401.16820](https://arxiv.org/abs/2401.16820) |
| **Improving Alignment and Robustness with Circuit Breakers** | Gray Swan / Zou et al. | 2024 | NeurIPS 2024 | [2406.04313](https://arxiv.org/abs/2406.04313) |
| **A Watermark for Large Language Models** | Kirchenbauer, Geiping et al. (UMD) | 2023 | ICML 2023 | [2301.10226](https://arxiv.org/abs/2301.10226) |

---

## 3. Conference Talks

### Black Hat

**Black Hat USA 2026** (August 5–7, Las Vegas)

- Full-day AI Summit on August 5. Sessions span AI-accelerated attacks, agentic AI threat landscapes, AI infrastructure exploitation, and AI for defensive security operations. Schedule TBA. [blackhat.com/us-26](https://www.blackhat.com/us-26/)

**Black Hat Asia 2026** (April 21–24, Singapore)

- AI Security Summit alongside the main briefings program. Sessions cover AI-driven attacks, enterprise AI hardening, agentic AI threat landscapes, and practical GenAI threat intelligence using RAG and multi-agent workflows. [blackhat.com/asia-26](https://www.blackhat.com/asia-26/)

**Black Hat USA 2025**

- **"AI Enterprise Compromise: 0Click Exploit Methods"** — Michael Bargury & Tamir Ishay Sharbat (Zenity Labs). Silent hijacking of enterprise AI agents (Jira, GitHub Copilot Studio, Slack) via zero-click MCP exploit chains. [blackhat.com/us-25](https://www.blackhat.com/us-25/)
- **"Breaking Out of the AI Cage: Pwning AI Providers with NVIDIA Vulnerabilities"** — Container escapes via CVE-2024-0132, CVE-2025-23266, CVE-2025-23319 affecting GPU cloud infrastructure. [YouTube](https://www.youtube.com/watch?v=5RH0StmV7Eo)
- **"LLMDYARA: LLMs-Driven Automated YARA Rules Generation"** — Automated malware YARA rule creation using LLMs. [Slides](https://i.blackhat.com/BH-USA-25/Presentations/USA-25-Wang-LLMDYara-LLMs-Driven-Automated-YARA.pdf)
- **"Autonomous Timeline Analysis and Threat Hunting: An AI Agent for Timesketch"** — Sec-Gemini digital forensic agent for log analysis. [YouTube](https://www.youtube.com/watch?v=9EA7kz4bGvQ) · [Google Cloud blog](https://cloud.google.com/blog/products/identity-security/your-guide-to-google-cloud-security-at-black-hat-usa-2025)

**Black Hat Europe 2024**

- **"SpAIware & More: Advanced Prompt Injection Exploits in LLM Applications"** — Johann Rehberger. Persistent memory injection and advanced injection chains. [blackhat.com/eu-24](https://www.blackhat.com/eu-24/)

**Black Hat USA 2024**

- **"Practical LLM Security: Takeaways From a Year in the Trenches"** — Richard Harang (NVIDIA). Slides: [PDF](http://i.blackhat.com/BH-US-24/Presentations/US24-Harang-Practical-LLM-Security-Takeaways-From-Wednesday.pdf)
- **"From MLOps to MLOops: Exposing the Attack Surface of Machine Learning Platforms"** — Shachar Menashe (JFrog). Slides: [PDF](http://i.blackhat.com/BH-US-24/Presentations/US24-Menashe-From-MLOps-To-MLOops.pdf)
- **"Isolation or Hallucination? Hacking AI Infrastructure Providers for Fun and Weights"** — Hillai Ben-Sasson & Sagi Tzadik (Wiz). Cross-tenant attacks on Hugging Face, Replicate, SAP AI Core.
- **"Deep Backdoors in Deep Reinforcement Learning Agents"** — Mavroudis et al. (Alan Turing Institute). Slides: [PDF](http://i.blackhat.com/BH-US-24/Presentations/US24-Mavroudis-Deep-Backdoors-in-Deep-Reinforcement-Learning-Agents-Wednesday.pdf)
- **"What Lies Beneath the Surface? Evaluating LLMs for Offensive Cyber Capabilities"** — Kouremetis et al. (MITRE). Slides: [PDF](http://i.blackhat.com/BH-US-24/Presentations/BHUS24-Kouremetis-WhatLiesBeneathTheSurface-8Aug2024.pdf)
- Full AI talk index across BSidesLV + Black Hat + DEF CON 2024: [tldrsec.com](https://tldrsec.com/p/tldr-every-ai-talk-bsideslv-blackhat-defcon-2024)

**Black Hat Asia 2024**

- **"LLM4Shell: Discovering and Exploiting RCE in LLM-Integrated Applications"** — RCE vulnerabilities in LLM-integrated apps. Slides: [PDF](https://i.blackhat.com/Asia-24/Presentations/bh-asia-2024-llm4shell.pdf)

**Black Hat USA 2023**

- **"Compromising LLMs: The Advent of AI Malware"** — Kai Greshake & Christoph Endres. Indirect prompt injection weaponized as AI malware. Slides: [PDF](https://i.blackhat.com/BH-US-23/Presentations/US-23-Greshake-Compromising-LLMS.pdf)

### RSA Conference

**RSA Conference 2026** (March 23–26, San Francisco)

- Agentic security was the dominant theme. Key session: "Securing AI Agent Toolchains: Exploiting and Hardening MCP Servers." Cisco announced DefenseClaw open-source agentic security framework. Multiple vendor announcements on AI-SPM (AI Security Posture Management) tooling. [rsaconference.com](https://www.rsaconference.com/)

**RSA Conference 2025** (April 28 – May 1, San Francisco)

- 40% of 2,800+ session submissions were AI-related. Dominant theme: shift from GenAI to agentic AI systems. Key data point from SANS keynote: adversarial AI agent systems execute attack sequences 47× faster than human operators with 93% privilege escalation success rate.
- OWASP half-day event introduced the first OWASP Agentic Security Initiative guide: *Agentic AI — Threats and Mitigations*.
- NIST/MITRE joint session on progress toward a "Cyber AI" community profile under the AI RMF. [rsaconference.com](https://www.rsaconference.com/library/blog/day-2-recap-2025)

**RSA Conference 2024** (May 6–9, San Francisco)

- 100+ sessions on AI security. Primary themes: AI governance and responsible use, cybercriminal exploitation of GenAI (underground forums, AI-as-a-service for phishing and social engineering), and AI in security operations tooling. [rsaconference.com](https://www.rsaconference.com/events/2024-usa)

---

### DEF CON AI Village

Website: [aivillage.org/events](https://aivillage.org/events/) | X: [@aivillage_dc](https://x.com/aivillage_dc) | YouTube: [youtube.com/c/aivillage](https://www.youtube.com/c/aivillage)

**DEF CON 32 (2024) — AI Village** — [aivillage.org/events/defcon32](https://aivillage.org/events/defcon32/)

- **"garak: A Framework for Large Language Model Red Teaming"** — Derczynski et al. (NVIDIA). The open-source LLM vulnerability scanner.
- **"Evaluations and Guardrails Against Prompt Injection Attacks on LLM-Powered Applications"** — Nikolaidis & Ahmad (Meta). CyberSecEval benchmarks + PromptGuard.
- **"ConfusedPilot: Data Corruption and Leakage by Misusing Copilot for Microsoft 365"** — RoyChowdhury et al. (UT Austin). [arXiv:2408.04870](https://arxiv.org/abs/2408.04870)
- **"MITRE ATLAS: AI Adversary Tactics Knowledge Base"** — Christina Liaghati (MITRE). Day 1 keynote.
- **"AI'll be watching you: Greybox Attacks against an Embedded AI"** — Tracey, Schulz, Bonner (HiddenLayer). Security camera AI bypass via adversarial inputs.
- **"FuzzLLM"** — Ian Harris (UC Irvine). Automated jailbreak fuzzing framework.
- **"Your AI Assistant Has a Big Mouth: A New Side-Channel Attack"** — Ben-Gurion University. Intercepts and decrypts encrypted AI assistant conversation streams via token-length side channel.
- **"Taming the Beast: Inside the Llama 3 Red Team Process"** — Meta AI Safety team.

**DEF CON 31 (2023)**

- The Generative Red Team Challenge — largest public LLM red-team event ever held. Thousands of participants attacked models from Anthropic, Google, Hugging Face, Meta, NVIDIA, OpenAI, and Stability AI simultaneously.

---

### USENIX Security

Full proceedings free online: [usenix.org/conferences/past](https://www.usenix.org/conferences/past)

**USENIX Security 2026** — Accepted AI security papers (conference Aug 12–14, Baltimore):

- **"The Prompt Stealing Fallacy: Rethinking Metrics, Attacks, and Defenses"** — Rethinks prompt extraction methodology; argues current metrics overstate attack success. [usenix.org](https://www.usenix.org/conference/usenixsecurity26)

**USENIX Security 2025** — Accepted AI security papers:

- **"PoisonedRAG: Knowledge Corruption Attacks to RAG"** — Zou et al. [arXiv:2402.07867](https://arxiv.org/abs/2402.07867)
- **"The Crescendo Multi-Turn Jailbreak Attack"** — Russinovich et al. (Microsoft). [arXiv:2404.01833](https://arxiv.org/abs/2404.01833)

**USENIX Security 2024** — Selected AI security papers:

- **"Formalizing and Benchmarking Prompt Injection Attacks and Defenses"** — Liu et al. First formal framework for PI evaluation. [usenix.org](https://www.usenix.org/conference/usenixsecurity24/presentation/liu-yupei)
- **"PentestGPT: An LLM-empowered Automatic Penetration Testing Tool"** — Deng et al. Peer-reviewed evaluation of autonomous LLM pentest agents. [usenix.org](https://www.usenix.org/conference/usenixsecurity24/presentation/deng)
- **"CodeBreaker: LLM-Assisted Backdoor Attack on Code Completion Models"** — Evades static analysis tools. [arXiv:2406.06822](https://arxiv.org/abs/2406.06822)

---

### IEEE SaTML

Premier dedicated conference for ML security and trustworthiness. Annual. Full proceedings: [satml.org](https://satml.org/)

**SaTML 2025** — Selected papers:

- **"SoK: On the Offensive Potential of AI"** — 14-author systematization of AI offensive capabilities across cyberattacks, influence operations, and physical-world threats. [Project site](https://sok-offensive-ai.github.io/)
- **"SoK: Membership Inference Attacks on LLMs are Rushing Nowhere (and How to Fix It)"** — Shows most LLM MIA evaluations are methodologically flawed. [arXiv:2406.17975](https://arxiv.org/abs/2406.17975)
- **"Get My Drift? Catching LLM Task Drift with Activation Deltas"** — Prompt injection detection via internal model activations. [arXiv:2406.00799](https://arxiv.org/abs/2406.00799)
- **"SnatchML: Hijacking ML Models without Training Access"** — Model hijacking without requiring access to training data or model weights. [GitHub](https://github.com/ihsenLab/SnatchML) · [IEEE Xplore](https://ieeexplore.ieee.org/document/10992506)
- Full list: [satml.org/2025/accepted-papers](https://satml.org/2025/accepted-papers/)

**SaTML 2026** — Selected accepted papers:

- **"CHAI: Command Hijacking against Embodied AI"** — Prompt-based attack exploiting multimodal language interpretation vulnerabilities in vision-language models deployed in embodied systems. [arXiv:2510.00181](https://arxiv.org/abs/2510.00181)
- **"Smudged Fingerprints: A Systematic Evaluation of the Robustness of AI Image Fingerprints"** — Adversarial attacks on AI image fingerprinting and content provenance systems. [arXiv:2512.11771](https://arxiv.org/abs/2512.11771)
- **"Position: Mind the Gap — Closing the Growing Disconnect Between Vulnerability Disclosure and AI Security"** — IBM Research position paper on the gap between AI system vuln disclosure practices and security research. [IBM Research](https://research.ibm.com/publications/position-mind-the-gap-closing-the-growing-disconnect-between-vulnerability-disclosure-and-ai-security)
- Full list: [satml.org/accepted-papers](https://satml.org/accepted-papers)

**SaTML 2024** — Best papers:

- **"SoK: AI Auditing: The Broken Bus on the Road to AI Accountability"** — Birhane et al. Critical analysis of AI audit methodologies. [OpenReview](https://openreview.net/forum?id=TmagEd33w3)
- **"Data Redaction from Conditional Generative Models"** — Kong & Chaudhuri. [OpenReview](https://openreview.net/forum?id=THrMIQDs7U)
- Full list: [satml.org/2024/accepted-papers](https://satml.org/2024/accepted-papers/)

---

### CAMLIS

Applied ML-for-security practitioner conference. Annual, Washington D.C. area. Proceedings and slides at [camlis.org](https://www.camlis.org/) | YouTube: [youtube.com/@camlis499](https://www.youtube.com/@camlis499)

**CAMLIS 2025** — Selected talks:

- **"ShadowLogic: Hidden Backdoors in Any Whitebox LLM"** — Amelia Kawasaki. Persistent backdoor insertion into LLMs without modifying weights. [camlis.org](https://www.camlis.org/amelia-kawasaki-2025)
- **"A Framework for Adaptive Multi-Turn Jailbreak Attacks on LLMs"** — Javad Rafiei Asl. Automated multi-turn attack generation adapting to model defenses. [camlis.org](https://www.camlis.org/javad-rafiei-asl-2025)
- **"LLM Salting: From Rainbow Tables to Jailbreaks"** — Tamás Vörös. Pre-computation attacks on LLM safety filters. [camlis.org](https://www.camlis.org/tamas-voros-2025)
- **"Attack Surfaces in Computer Use Agents: A Practical Taxonomy"** — Daniel Jones. Systematic taxonomy of attack surfaces specific to computer-use AI agents. [camlis.org](https://www.camlis.org/daniel-jones-2025) *(CAMLIS RED Track)*
- **"Importing Phantoms: Measuring LLM Package Hallucination Vulnerabilities"** — Arjun Krishna. Quantifies hallucinated package names exploitable for supply chain attacks. [camlis.org](https://www.camlis.org/arjun-krishna-2025)

**CAMLIS 2024** — Selected talks:

- **"PyRIT: A Framework for Security Risk Identification and Red Teaming in Generative AI Systems"** — Gary Lopez Munoz (Microsoft). Introduction of PyRIT, Microsoft's open-source LLM red teaming framework. [camlis.org](https://www.camlis.org/)
- **"Defending Against Indirect Prompt Injection Attacks With Spotlighting"** — Keegan Hines. Input marking technique that separates trusted instructions from untrusted data. [camlis.org](https://www.camlis.org/)
- **"LLM Backdoor Activations Stick Together"** — Tamás Vörös. Activation-space analysis to detect backdoored LLMs. [camlis.org](https://www.camlis.org/)
- **"LLM Agents for Vulnerability Identification and Verification of CVEs"** — Rodrigo Bersa & Tadesse Zemichael. Automated CVE reproduction and triage using LLM agents. [camlis.org](https://www.camlis.org/)

**CAMLIS 2023** — Selected talks:

- **"Security Issues in Generative AI"** — Tom Goldstein (University of Maryland). Foundational adversarial ML issues in LLMs. [camlis.org](https://www.camlis.org/)
- **"LLM Prompt Injection: Attacks and Defenses"** — Gary Lopez Munoz. Early practitioner-focused treatment of prompt injection attack taxonomy and mitigations. [camlis.org](https://www.camlis.org/)
- **"Model Leeching: An Extraction Attack Targeting LLMs"** — Lewis Birch. Model extraction methodology adapted for large language models. [camlis.org](https://www.camlis.org/)

---

### Talk Archives on YouTube

| Channel | What It Has |
|---------|------------|
| [AI Village (DEF CON)](https://www.youtube.com/c/aivillage) | All past DEF CON AI Village talks — the primary offensive AI security archive |
| [DEF CON Official](https://www.youtube.com/@DEFCONConference) | Full DEF CON main stage and village talks |
| [Black Hat Official](https://www.youtube.com/@BlackHatOfficialYT) | Black Hat USA/EU/Asia recordings, free 90 days after each event |
| [USENIX](https://www.youtube.com/@UsenixOrg/videos) | Full USENIX Security, Enigma, and SOUPS proceedings with video |
| [CAMLIS](https://www.youtube.com/@camlis499) | Applied ML-for-security practitioner talks |

---

## 4. Tools — Offense & Red Teaming

### LLM Red Teaming

| Tool | By | What It Does | Link |
|------|----|-------------|------|
| **Garak** | NVIDIA | Automated LLM vulnerability scanner. 120+ probe categories: jailbreaks, prompt injection, hallucination, toxicity, data extraction. Plugin architecture for custom probes. The standard starting point for automated LLM red teaming. arXiv: [2406.11036](https://arxiv.org/abs/2406.11036) | [github.com/NVIDIA/garak](https://github.com/NVIDIA/garak) |
| **PyRIT** | Microsoft Azure | Red teaming framework for generative AI. Multi-turn attack orchestration, attack memory, scoring pipelines. Enterprise red team programs. | [github.com/Azure/PyRIT](https://github.com/Azure/PyRIT) |
| **promptfoo** | promptfoo (acquired by OpenAI, Mar 2026) | CI/CD-integrated LLM testing. YAML test cases against any LLM API. Red team mode generates adversarial prompts automatically. Remains MIT licensed and open source post-acquisition; technology being integrated into OpenAI's agentic security stack. | [github.com/promptfoo/promptfoo](https://github.com/promptfoo/promptfoo) |
| **FuzzyAI** | CyberArk | Automated jailbreak fuzzing. Systematically probes LLMs using a catalog of attack templates. | [github.com/cyberark/FuzzyAI](https://github.com/cyberark/FuzzyAI) |
| **BrokenHill** | BishopFox | Production-quality GCG (Greedy Coordinate Gradient) adversarial attack implementation. Automates generation of adversarial suffixes that reliably bypass aligned LLMs. | [github.com/BishopFox/BrokenHill](https://github.com/BishopFox/BrokenHill) |
| **EasyJailbreak** | EasyJailbreak org | Unified framework for 11+ jailbreak techniques (GCG, PAIR, AutoDAN, TAP, and others) behind a single interface. Compare attack effectiveness without implementing each method separately. | [github.com/EasyJailbreak/EasyJailbreak](https://github.com/EasyJailbreak/EasyJailbreak) |
| **Parseltongue (P4RS3LT0NGV3)** | Arcanum-Sec | LLM adversarial payload generator. Transforms inputs through 50+ encoding, cipher, and steganographic formats to test content filter bypass. Paired with the ARC PI Taxonomy. | [github.com/Arcanum-Sec/P4RS3LT0NGV3](https://github.com/Arcanum-Sec/P4RS3LT0NGV3) |
| **WhistleBlower** | Repello AI | Offensive tool for inferring LLM system prompts and discovering hidden capabilities from production AI API outputs. Use for reconnaissance before a full red team engagement. | [github.com/Repello-AI/whistleblower](https://github.com/Repello-AI/whistleblower) |
| **Giskard** | Giskard AI | LLM and ML testing framework. Pre-deployment evaluation covering hallucination, prompt injection, bias, output quality. Integrates as CI gate. | [github.com/Giskard-AI/giskard](https://github.com/Giskard-AI/giskard) |
| **ARTkit** | BCG-X | Automated prompt-based testing for GenAI apps. Multi-turn adversarial test flows, custom attack plugins, evaluation metrics. | [github.com/BCG-X-Official/artkit](https://github.com/BCG-X-Official/artkit) |
| **Agentic Security** | msoedov | Open-source LLM vulnerability scanner for agentic workflows. Runtime testing covering jailbreaks, multimodal attacks, fuzzing, and prompt injection across LLM agents. | [github.com/msoedov/agentic_security](https://github.com/msoedov/agentic_security) |
| **DeepTeam** | Confident AI | LLM red teaming framework and CI regression gate. Structured attack scenarios, pre-deployment safety regression testing. 2026 update adds OWASP_ASI_2026 agentic security framework. | [github.com/confident-ai/deepteam](https://github.com/confident-ai/deepteam) |
| **Novee** | Novee | Autonomous AI red teaming agent for LLM applications. Simulates chained attack scenarios against any model provider. Launched at RSAC 2026. | [helpnetsecurity.com](https://www.helpnetsecurity.com/2026/03/24/novee-ai-red-teaming-for-llm-applications/) |
| **Wiz AI Cyber Model Arena** | Wiz | Open real-world benchmark for evaluating AI agents' offensive security capabilities. 257 challenges across zero-day discovery, CVE exploitation, web security, and cloud security. | [wiz.io/blog](https://www.wiz.io/blog/introducing-ai-cyber-model-arena-a-real-world-benchmark-for-ai-agents-in-cybersec) |
| **augustus** | Praetorian | Go-based LLM security testing framework. 190+ probes, 28 provider integrations, single binary deployment. Concurrent scanning, rate limiting, retry logic. Purpose-built for production red team workflows. | [github.com/praetorian-inc/augustus](https://github.com/praetorian-inc/augustus) |
| **llamator** | LLAMATOR-Core | Testing framework for LLM vulnerabilities across multiple categories. Structured attack scenarios with reporting. | [github.com/LLAMATOR-Core/llamator](https://github.com/LLAMATOR-Core/llamator) |
| **Spikee** | WithSecure Labs | Toolkit for testing LLM applications, RAG pipelines, and guardrail configurations against prompt injection and jailbreaking. | [github.com/WithSecureLabs/spikee](https://github.com/WithSecureLabs/spikee) |
| **G0DM0D3** | elder-plinius | Multi-model jailbreak research interface. Sends identical payloads to 50+ models via OpenRouter for comparative attack analysis. Includes GODMODE CLASSIC attack combos, Parseltongue perturbation engine with 33 red team techniques, and AutoTune adaptive sampling. | [github.com/elder-plinius/G0DM0D3](https://github.com/elder-plinius/G0DM0D3) |
| **BlackIce** | Databricks | Containerized red team toolkit for LLMs and classical ML models — the Kali Linux equivalent for AI security assessments. Reproducible container image with standardized AI evaluation tools. | [github.com/databricks/containers/tree/master/ubuntu/blackice](https://github.com/databricks/containers/tree/master/ubuntu/blackice) |
| **OpenPromptInjection** | liu00222 | Benchmark framework for prompt injection attacks and defenses. Evaluates attack and mitigation effectiveness in a controlled setting. | [github.com/liu00222/Open-Prompt-Injection](https://github.com/liu00222/Open-Prompt-Injection) |
| **llm-attacks (GCG)** | llm-attacks org | Reference implementation for universal and transferable adversarial attacks on aligned LLMs (GCG attack — Zou et al., ICLR 2024). Foundation for any GCG-based research. | [github.com/llm-attacks/llm-attacks](https://github.com/llm-attacks/llm-attacks) |
| **Dropbox LLM Security** | Dropbox Research | LLM security research code and results from Dropbox's security team. Focuses on LLM integration attack surfaces. | [github.com/dropbox/llm-security](https://github.com/dropbox/llm-security) |
| **OpenRT** | AI45Lab | Open-source red teaming framework for multimodal LLMs. 42+ attack methods across white-box and black-box categories, covering text, image, and vision-language models. | [github.com/AI45Lab/OpenRT](https://github.com/AI45Lab/OpenRT) |
| **JailbreakingLLMs (PAIR)** | Chao et al. | Official implementation of the PAIR algorithm. Attacker LLM iteratively refines jailbreak prompts until the target complies — achieving jailbreaks in ~20 queries. CLI supports OpenAI, Anthropic, and Google models via `--attack-model` / `--target-model` / `--judge-model` flags. | [github.com/patrickrchao/JailbreakingLLMs](https://github.com/patrickrchao/JailbreakingLLMs) |
| **AutoDAN** | Liu et al. (ICLR 2024) | Hierarchical genetic algorithm for generating fluent, stealthy jailbreak prompts that evade perplexity-based filters that block GCG suffixes. Supports Llama-2, Vicuna, GPT-3.5, GPT-4. Full training and evaluation pipeline included. | [github.com/SheltonLiu-N/AutoDAN](https://github.com/SheltonLiu-N/AutoDAN) |

### Adversarial ML Tools

| Tool | By | What It Does | Link |
|------|----|-------------|------|
| **Adversarial Robustness Toolbox (ART)** | IBM Trusted AI | Comprehensive adversarial ML library. Evasion, poisoning, extraction, and inference attacks. TensorFlow, PyTorch, scikit-learn, Keras, XGBoost. | [github.com/Trusted-AI/adversarial-robustness-toolbox](https://github.com/Trusted-AI/adversarial-robustness-toolbox) |
| **Foolbox** | Bethge Lab (Tübingen) | Adversarial example library. 15+ attack methods (FGSM, PGD, C&W, DeepFool). PyTorch and JAX native. More approachable than ART for image model testing. | [github.com/bethgelab/foolbox](https://github.com/bethgelab/foolbox) |
| **CleverHans** | Google Brain / Goodfellow | Original adversarial ML library. Strong research pedigree. FGSM, PGD, Carlini-Wagner. Primarily TensorFlow. | [github.com/cleverhans-lab/cleverhans](https://github.com/cleverhans-lab/cleverhans) |
| **TextAttack** | QData (UVA) | NLP adversarial attack and augmentation. Character-, word-, and sentence-level perturbations for text classifier robustness testing. | [github.com/QData/TextAttack](https://github.com/QData/TextAttack) |
| **ML Privacy Meter** | Privacy Trust Lab | Quantifies training data privacy risk via membership inference attacks. Use for GDPR impact assessments. | [github.com/privacytrustlab/ml_privacy_meter](https://github.com/privacytrustlab/ml_privacy_meter) |
| **PrivacyRaven** | Trail of Bits | Privacy attack testing: model inversion and label-only membership inference attacks. (archived Sep 2025) | [github.com/trailofbits/PrivacyRaven](https://github.com/trailofbits/PrivacyRaven) |
| **Counterfit** | Microsoft Azure | CLI automation for adversarial testing of classical ML models exposed via APIs. Orchestrates ART attacks against deployed prediction endpoints. | [github.com/Azure/counterfit](https://github.com/Azure/counterfit) |
| **BadDiffusion** | IBM Research | Official implementation of "How to Backdoor Diffusion Models?" (CVPR 2023). Demonstrates backdoor attacks against image diffusion models. | [github.com/IBM/BadDiffusion](https://github.com/IBM/BadDiffusion) |
| **secml-torch** | PRALab | SecML-Torch: library for robustness evaluation of deep learning models. Implements evasion attacks with certified defenses. | [github.com/pralab/secml-torch](https://github.com/pralab/secml-torch) |
| **ai-exploits** | ProtectAI | Collection of exploits and scanning templates (Metasploit modules, Nuclei templates) for vulnerabilities in ML infrastructure — MLflow, Ray, BentoML, Gradio, and more. | [github.com/protectai/ai-exploits](https://github.com/protectai/ai-exploits) |
| **Deep-pwning** | cchio | Lightweight framework for robustness testing of ML models against motivated adversaries. Supports multiple attack objectives. | [github.com/cchio/deep-pwning](https://github.com/cchio/deep-pwning) |
| **Charcuterie** | moohax | Code execution techniques targeting ML-adjacent libraries. Catalogs memory corruption and arbitrary code execution paths in ML ecosystems. | [github.com/moohax/Charcuterie](https://github.com/moohax/Charcuterie) |
| **Malware Env for OpenAI Gym** | Endgame | RL environment for malware evasion research. Agents learn PE file manipulation actions to evade AV detection — tests ML-based antivirus robustness. | [github.com/endgameinc/gym-malware](https://github.com/endgameinc/gym-malware) |

### Agentic & MCP Attack Tools

| Tool | By | What It Does | Link |
|------|----|-------------|------|
| **AgentDojo** | ETH Zurich | Benchmark and testing framework for agent security. Evaluates agents against goal-directed attacks: tool hijacking, indirect injection, task manipulation. | [github.com/ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo) |
| **MCP Inspector** | MCP project | Reverse engineering and debugging for MCP servers. Inspect tool definitions, trace calls, identify SSRF and path traversal vectors. Required for any MCP security review. | [github.com/modelcontextprotocol/inspector](https://github.com/modelcontextprotocol/inspector) |
| **AI-Infra-Guard** | Tencent | Integrated AI red teaming platform: AI infrastructure vulnerability scanning (~400 CVEs across 30+ AI components), MCP server risk scanning, and jailbreak evaluation in a single tool. | [github.com/Tencent/AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) |
| **vger** | JosephTLucas (NVIDIA) | Interactive CLI for attacking authenticated Jupyter Notebook instances — enumerate kernels, execute arbitrary code, exfiltrate data from ML training environments. | [github.com/JosephTLucas/vger](https://github.com/JosephTLucas/vger) |
| **AI-Exploits** | ProtectAI | Working PoC exploits for known CVEs in AI/ML infrastructure — MLflow, Ray, Hugging Face Spaces, LangChain. Test whether your AI stack is patched. | [github.com/protectai/ai-exploits](https://github.com/protectai/ai-exploits) |
| **Invariant Analyzer** | Invariant Labs | Security analysis of AI agent execution traces. Detects policy violations, prompt injection in tool outputs, sensitive data leakage, and unsafe data flows. | [github.com/invariantlabs-ai/invariant](https://github.com/invariantlabs-ai/invariant) |
| **MCP Injection Experiments** | Invariant Labs | Code snippets and PoCs to reproduce MCP tool poisoning attacks. Essential reference for testing tool description injections and cross-server escalation. | [github.com/invariantlabs-ai/mcp-injection-experiments](https://github.com/invariantlabs-ai/mcp-injection-experiments) |
| **mcp-for-security** | cyproxio | MCP servers for popular offensive security tools (SQLMap, FFUF, Nmap, Masscan). Integrates security testing into AI agentic workflows. | [github.com/cyproxio/mcp-for-security](https://github.com/cyproxio/mcp-for-security) |
| **mcp-security-hub** | FuzzingLabs | Growing collection of MCP servers for offensive security tools: Nmap, Ghidra, Nuclei, SQLMap, Hashcat. Exposes security tooling to AI assistants. | [github.com/FuzzingLabs/mcp-security-hub](https://github.com/FuzzingLabs/mcp-security-hub) |
| **julius** | Praetorian | LLM service fingerprinting tool. Detects 32+ AI services (Ollama, vLLM, LiteLLM, Hugging Face TGI) during pentests via HTTP-based fingerprinting. Use for attack surface mapping. | [github.com/praetorian-inc/julius](https://github.com/praetorian-inc/julius) |
| **a2a-scanner** | Cisco AI Defense | Scans A2A (Agent-to-Agent) protocol agents for security issues and potential threats. | [github.com/cisco-ai-defense/a2a-scanner](https://github.com/cisco-ai-defense/a2a-scanner) |

### Benchmarks & Evaluation

| Tool | By | What It Measures | Link |
|------|----|-----------------|------|
| **JailbreakBench** | JailbreakBench org | Standardized jailbreak evaluation with fixed test set and leaderboard. Reproducible comparison of attack and defense methods. NeurIPS 2024. | [github.com/JailbreakBench/jailbreakbench](https://github.com/JailbreakBench/jailbreakbench) |
| **HarmBench** | Center for AI Safety | LLM safety benchmark across harmful behaviors. Standardized leaderboard, multiple attack methods. | [github.com/centerforaisafety/HarmBench](https://github.com/centerforaisafety/HarmBench) |
| **CyberSecEval** | Meta (Purple Llama) | Evaluates LLM cybersecurity risk: insecure code generation, prompt injection, cyberattack assistance. Now at version 4 (CyberSOCEval + AutoPatchBench). | [github.com/meta-llama/PurpleLlama](https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks) |
| **HELM** | Stanford CRFM | Holistic LLM evaluation: accuracy, calibration, robustness, fairness, bias, toxicity, efficiency. Living benchmark with leaderboard. | [crfm.stanford.edu/helm](https://crfm.stanford.edu/helm/) |
| **Inspect AI** | UK AI Security Institute | Open-source evaluation framework for LLM safety and capability. Used by UK AISI for frontier model evaluations. | [github.com/UKGovernmentBEIS/inspect_ai](https://github.com/UKGovernmentBEIS/inspect_ai) |
| **PromptBench** | Microsoft Research | Adversarial prompt robustness. Tests LLM sensitivity to character-, word-, sentence-, and semantic-level perturbations. | [github.com/microsoft/promptbench](https://github.com/microsoft/promptbench) |
| **AIRTBench** | Dreadnode | Measures autonomous AI red teaming capability of language models — tests whether AI agents can perform offensive security tasks. | [github.com/dreadnode/AIRTBench-Code](https://github.com/dreadnode/AIRTBench-Code) |
| **RobustBench** | RobustBench org | Standardized adversarial robustness benchmark for ML models against adversarial perturbations and distribution shifts. Standard reference for robustness comparisons. | [robustbench.github.io](https://robustbench.github.io/) |
| **Lakera PINT Benchmark** | Lakera | Multilingual prompt injection detection benchmark. Four categories: injections, jailbreaks, hard negatives, benign. Enables reproducible evaluation of injection detection systems. | [github.com/lakeraai/pint-benchmark](https://github.com/lakeraai/pint-benchmark) |
| **BackdoorLLM** | — | Comprehensive LLM backdoor benchmark. Covers data poisoning, weight poisoning, and chain-of-thought backdoor attacks. Includes defense toolkit. NeurIPS 2025. | [github.com/bboylyg/BackdoorLLM](https://github.com/bboylyg/BackdoorLLM) |
| **Agent Security Bench (ASB)** | — | 10 agent scenarios, 400+ tools, 27 attack/defense methods for evaluating LLM agent security. ICLR 2025. | [arXiv:2410.02644](https://arxiv.org/abs/2410.02644) |
| **MLCommons AILuminate v1.0** | MLCommons | Industry-standard AI safety benchmark developed with major AI companies. Evaluates against standardized hazard taxonomy. Used as a common safety reporting baseline. | [mlcommons.org/ailuminate](https://mlcommons.org/ailuminate/) |
| **AgentDoG** | AI45Lab | Risk-aware evaluation and guarding framework for autonomous agents. Trajectory-level risk assessment to determine whether an agent's execution path contains safety risks across diverse application scenarios. | [github.com/AI45Lab/AgentDoG](https://github.com/AI45Lab/AgentDoG) |
| **RedBench** | Community | Universal red-team evaluation dataset aggregating 37 benchmark datasets, 29,362 samples, 22 risk categories, 19 domains. Standard comparison surface for attack/defense research. arXiv: [2601.03699](https://arxiv.org/abs/2601.03699) | [arxiv.org/abs/2601.03699](https://arxiv.org/abs/2601.03699) |
| **AIRTBench** | Dreadnode | 70-challenge autonomous AI red-teaming benchmark on the Crucible platform. Evaluates LLM ability to autonomously find and exploit AI/ML security vulnerabilities. Claude 3.7 Sonnet led at 61% success rate. | [github.com/dreadnode/AIRTBench-Code](https://github.com/dreadnode/AIRTBench-Code) |

### Vulnerable Labs & CTFs

Hands-on practice environments for AI security skills.

| Environment | Type | What It Teaches | Link |
|-------------|------|-----------------|------|
| **Memory Poisoning Lab** | Local teaching lab | Persistent memory poisoning, defense and repair limits using synthetic data and a scripted agent. | [github.com/RishabhPande/memory-poison-lab](https://github.com/RishabhPande/memory-poison-lab) |
| **Gandalf** | Web game | Prompt injection, progressive difficulty. Good first introduction. | [gandalf.lakera.ai](https://gandalf.lakera.ai/) |
| **PortSwigger Web Security Academy: Web LLM Attacks** | Free labs | LLM prompt injection, data exfiltration via LLMs, indirect injection. | [portswigger.net/web-security/llm-attacks](https://portswigger.net/web-security/llm-attacks) |
| **AI GOAT** | Vulnerable lab | Deliberately vulnerable LLM app for practicing injection, data leakage, attack chains. | [github.com/dhammon/ai-goat](https://github.com/dhammon/ai-goat) |
| **Damn Vulnerable LLM Agent** | Vulnerable lab | Vulnerable agentic system: tool misuse, injection via tool output, privilege escalation. | [github.com/ReversecLabs/damn-vulnerable-llm-agent](https://github.com/ReversecLabs/damn-vulnerable-llm-agent) |
| **Damn Vulnerable MCP Server** | Vulnerable lab | Deliberately vulnerable MCP server implementation for learning MCP security exploitation: tool poisoning, path traversal, injection via tool responses. | [github.com/harishsg993010/damn-vulnerable-MCP-server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) |
| **Vulnerable MCP Servers Lab** | Vulnerable lab | Collection of deliberately vulnerable MCP servers for pentesting practice. | [github.com/appsecco/vulnerable-mcp-servers-lab](https://github.com/appsecco/vulnerable-mcp-servers-lab) |
| **OWASP WrongSecrets — LLM Exercise** | CTF challenge | Challenge #32 in OWASP WrongSecrets specifically covering LLM security misconfigurations and secret handling. Run locally via Docker. | [github.com/OWASP/wrongsecrets](https://github.com/OWASP/wrongsecrets) |
| **MyLLMAuto** | CTF lab | Vulnerable multi-chain LLM app. 5 flags covering cross-chain prompt injection. | [github.com/Arcanum-Sec/MyLLMAuto](https://github.com/Arcanum-Sec/MyLLMAuto) |
| **Microsoft AI Red Teaming Playground Labs** | Guided labs | 12 structured challenges: prompt injection, metaprompt extraction, Crescendo multi-turn attacks. | [github.com/microsoft/AI-Red-Teaming-Playground-Labs](https://github.com/microsoft/AI-Red-Teaming-Playground-Labs) |
| **Crucible (Dreadnode)** | Year-round CTF | AI/ML challenges: adversarial ML, model extraction, LLM attacks. Available year-round. | [app.dreadnode.io](https://app.dreadnode.io/) |
| **AI Village CTF (DEF CON)** | Annual CTF | Offensive AI challenges at DEF CON. Past challenges archived after each event. | [aivillage.org/events](https://aivillage.org/events/) |
| **HackAPrompt** | Competition | Large-scale prompt injection competition with structured difficulty levels. Past competitions archived with solutions. | [hackaprompt.com](https://www.hackaprompt.com/) |
| **PromptAirlines** | Wiz | Prompt injection CTF styled as an airline booking AI. Direct + indirect injection + context manipulation. No registration required. | [promptairlines.com](https://promptairlines.com/) |
| **FinBot CTF** | OWASP GenAI | Agentic AI CTF simulating a financial AI agent. Tool injection, privilege escalation, agent hijacking. | [genai.owasp.org](https://genai.owasp.org/resource/finbot-agentic-ai-capture-the-flag-ctf-application/) |
| **MyLLMBank / MyLLMDoctor** | Vulnerable apps | Banking and medical LLM app simulations with domain-specific AI attack scenarios. | [myllmbank.com](https://myllmbank.com/) · [myllmdoc.com](https://myllmdoc.com/) |
| **8kSec AI Exploitation Challenges** | Free guided labs | Hands-on exploitation of AI systems — prompt injection, agent misuse, and related attack techniques. Certificate of completion. | [academy.8ksec.io/course/ai-exploitation-challenges](https://academy.8ksec.io/course/ai-exploitation-challenges) |

---

## 5. Tools — Defense & Detection

### Guardrails & Output Safety

| Tool | By | What It Does | Link |
|------|----|-------------|------|
| **LlamaFirewall** | Meta (Purple Llama) | Runtime security framework for agentic AI. Combines PromptGuard 2 (injection/jailbreak detection), AlignmentCheck (agent misalignment), and CodeShield (unsafe code generation). Wraps multi-step agent pipelines. | [github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall) |
| **LlamaGuard** | Meta (Purple Llama) | Open-source content safety classifier. Deploy as pre/post-filter on any LLM pipeline. Customizable unsafe category taxonomy. | [github.com/meta-llama/PurpleLlama](https://github.com/meta-llama/PurpleLlama/tree/main/Llama-Guard) |
| **LLM Guard** | ProtectAI | Comprehensive input/output scanner: prompt injection, PII detection, toxicity, jailbreak detection, ban topics, code security. Self-hosted or API. | [github.com/protectai/llm-guard](https://github.com/protectai/llm-guard) |
| **NeMo Guardrails** | NVIDIA | Programmable guardrail framework. Topical, fact-checking, and jailbreak detection rails in a declarative config. LangChain integration. | [github.com/NVIDIA/NeMo-Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) |
| **Guardrails AI** | Guardrails AI | Python library for structured LLM output validation. Define validators, enforce schemas, handle re-prompting on failure. | [github.com/guardrails-ai/guardrails](https://github.com/guardrails-ai/guardrails) |
| **Presidio** | Microsoft | PII/PHI detection and redaction for text, images, and structured data. Use as pre-processing before sending data to LLMs. | [github.com/microsoft/presidio](https://github.com/microsoft/presidio) |
| **Vigil LLM** | deadbits | Real-time detection of prompt injection and jailbreak attempts. Detection modules: YARA rule matching, vector similarity, canary token monitoring, LLM-based scoring. | [github.com/deadbits/vigil-llm](https://github.com/deadbits/vigil-llm) |
| **Prompt Injection Defenses** | tl;dr sec | Curated catalog of every known practical defense against prompt injection — from input sanitization to architectural controls. | [github.com/tldrsec/prompt-injection-defenses](https://github.com/tldrsec/prompt-injection-defenses) |
| **AI Fairness 360 (AIF360)** | IBM / Trusted AI | Fairness metrics and bias mitigation algorithms for ML datasets and models. Pre/in/post-processing approaches. Relevant to EU AI Act Art. 10 data governance. | [github.com/Trusted-AI/AIF360](https://github.com/Trusted-AI/AIF360) |
| **LiteLLM** | BerriAI | Open-source proxy and AI gateway for 100+ LLM providers. Security features: per-user/team rate limiting, request/response logging, secret key management. | [github.com/BerriAI/litellm](https://github.com/BerriAI/litellm) |
| **ZenGuard AI** | ZenGuard | Fast trust layer for AI agents. Policy-driven input/output filtering and safety enforcement. | [github.com/ZenGuard-AI/fast-llm-security-guardrails](https://github.com/ZenGuard-AI/fast-llm-security-guardrails) |
| **vibraniumdome** | genia-dev | Full-stack LLM WAF for agents: security governance, auditing, and policy-driven control over agent-model interactions. | [github.com/genia-dev/vibraniumdome](https://github.com/genia-dev/vibraniumdome) |
| **LocalMod** | KOKOSde | Self-hosted content moderation API with prompt injection detection, toxicity filtering, PII detection, and NSFW classification. Runs 100% offline — no external calls. | [github.com/KOKOSde/localmod](https://github.com/KOKOSde/localmod) |
| **AprielGuard** | ServiceNow AI | 8B parameter safety-security safeguard model trained for multi-domain harm detection and content policy enforcement. | [huggingface.co/blog/ServiceNow-AI/aprielguard](https://huggingface.co/blog/ServiceNow-AI/aprielguard) |
| **Safe Zone** | thyrisAI | Open-source PII detection and guardrails engine. Prevents sensitive data from leaking to LLMs and third-party APIs. | [github.com/thyrisAI/safe-zone](https://github.com/thyrisAI/safe-zone) |
| **rebuff** | woop | Prompt injection detector using multi-layer detection: heuristics, LLM analysis, and vector similarity against known attacks. (archived May 2025) | [github.com/woop/rebuff](https://github.com/woop/rebuff) |
| **OpenGuardrails** | openguardrails.com | Open-source runtime security framework for AI agents. Protects against prompt injection, data leakage, and unsafe behavior with a policy-driven control layer. arXiv: [2510.19169](https://arxiv.org/abs/2510.19169) | [openguardrails.com](https://openguardrails.com/) |

### Model & Supply Chain Security

| Tool | By | What It Does | Link |
|------|----|-------------|------|
| **ModelScan** | ProtectAI | Scans ML model files (pickle, PyTorch .pt, TF SavedModel, Keras) for malicious serialized code before loading. Integrate into CI/CD. | [github.com/protectai/modelscan](https://github.com/protectai/modelscan) |
| **Fickling** | Trail of Bits | Static analysis of pickle files. Decompiles pickle bytecode and identifies malicious operations. More analytical than ModelScan. Use both. | [github.com/trailofbits/fickling](https://github.com/trailofbits/fickling) |
| **picklescan** | mmaitre314 | Lightweight pickle file scanner. Fast for quick scanning of model repositories. | [github.com/mmaitre314/picklescan](https://github.com/mmaitre314/picklescan) |
| **SafeTensors** | Hugging Face | Safe serialization format for ML model weights. Structural alternative to pickle that eliminates arbitrary code execution during model loading. Use as first line of defense for models you control. | [github.com/huggingface/safetensors](https://github.com/huggingface/safetensors) |
| **ML-BOM (CycloneDX)** | OWASP CycloneDX | Machine Learning Bill of Materials. Catalogs models, datasets, training code, and dependencies. CISA-recommended for AI supply chain transparency. | [cyclonedx.org/capabilities/mlbom](https://cyclonedx.org/capabilities/mlbom/) |
| **TruffleHog** | Truffle Security | Secret scanning with native support for Jupyter Notebooks and Hugging Face repositories. Detects leaked API keys, model tokens, and credentials in notebooks and model cards. | [github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) |
| **Model Signing (Sigstore)** | Sigstore / Hugging Face | Cryptographic signing and verification of ML model artifacts using Sigstore. Allows downstream users to verify a model came from the claimed source and has not been tampered with. | [github.com/sigstore/model-transparency](https://github.com/sigstore/model-transparency) |
| **lm-watermarking** | Kirchenbauer, Geiping et al. (UMD) | Reference implementation of the Maryland watermarking technique for LLM outputs. Embeds a statistically imperceptible signal verifiable by a party with the watermark key. | [github.com/jwkirchenbauer/lm-watermarking](https://github.com/jwkirchenbauer/lm-watermarking) |
| **mcp-scan** | Invariant Labs | Static and dynamic security scanner for MCP server configurations. Detects prompt injection in tool descriptions, permission over-grants, unsafe server configurations. | [github.com/invariantlabs-ai/mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) |
| **ToolHive** | Stacklok | Platform for running and managing MCP servers securely. Isolates each server in its own container with permission scoping, secret management, and defined network/filesystem access. | [github.com/stacklok/toolhive](https://github.com/stacklok/toolhive) |
| **SlowMist MCP Security Checklist** | SlowMist | Structured security verification checklist for MCP server implementations, client integrations, and deployment configurations. | [github.com/slowmist/MCP-Security-Checklist](https://github.com/slowmist/MCP-Security-Checklist) |
| **ProtectAI Sightline** | ProtectAI | AI/ML supply chain vulnerability database. CVEs in MLflow, Ray, Kubeflow, Hugging Face, LangChain with Nuclei scanner templates and PoC exploits. | [sightline.protectai.com](https://sightline.protectai.com/) |
| **Vulnerable MCP Project** | Community | Live database tracking CVEs and security vulnerabilities specifically in the MCP ecosystem, with per-CVE technical breakdowns and patch status. | [vulnerablemcp.info](https://vulnerablemcp.info/) |

> **Format gap:** ModelScan, Fickling, and picklescan cover pickle, PyTorch .pt, TF SavedModel, and Keras formats — but not GGUF (the dominant format for llama.cpp-based local model serving: Ollama, LM Studio). No production-ready security scanner covers GGUF as of early 2026.

### Production Monitoring

| Tool | By | What It Does | Link |
|------|----|-------------|------|
| **Alibi Detect** | Seldon | Drift, outlier, and adversarial input detection in production. Monitors model input distribution in real time. | [github.com/SeldonIO/alibi-detect](https://github.com/SeldonIO/alibi-detect) |
| **LangKit** | WhyLabs | LLM observability metrics toolkit. Tracks prompt injection similarity, PII exposure, hallucination, relevance, and toxicity as real-time metrics. | [github.com/whylabs/langkit](https://github.com/whylabs/langkit) |
| **Agentic Radar** | splx-ai | Open-source CLI security scanner for agentic AI frameworks. Scans LangChain, CrewAI, AutoGen for known security anti-patterns. Static analysis. | [github.com/splx-ai/agentic-radar](https://github.com/splx-ai/agentic-radar) |
| **Beelzebub** | Community | AI-powered honeypot framework. Deploys decoy LLM-backed services that log attacker probes while responding convincingly. | [github.com/mariocandela/beelzebub](https://github.com/mariocandela/beelzebub) |
| **Cisco DefenseClaw** | Cisco | Open-source framework for securing AI agents throughout their lifecycle. Content scanner inspects every message flowing in and out of agent execution loops. Announced RSAC 2026. | [helpnetsecurity.com](https://www.helpnetsecurity.com/2026/02/11/cisco-agentic-ai-protection/) |
| **Miggo AI-BOM & MCP Monitoring** | Miggo Security | Runtime defense with AI Bill of Materials discovery, behavioral drift detection for agents, and MCP-aware monitoring to flag abnormal tool access and risky chaining patterns. | [securityboulevard.com](https://securityboulevard.com/2026/03/miggo-security-expands-runtime-defense-platform-with-ai-bom-agentic-detection-and-mcp-monitoring/) |
| **Straiker Defend AI** | Straiker | Real-time runtime security for AI agents. Inspects every prompt, reasoning step, and tool call. Context-aware guardrails with sub-100ms latency. | [straiker.ai](https://www.straiker.ai/products/defend-ai) |

### Agent Runtime Security & Sandboxing

Tools for isolating agent execution and enforcing policy over what agents can access, write, or exfiltrate.

| Tool | By | What It Does | Link |
|------|----|-------------|------|
| **E2B** | E2B | SDK + self-hostable infra for running untrusted, LLM-generated code in isolated Firecracker microVM cloud sandboxes. | [github.com/e2b-dev/E2B](https://github.com/e2b-dev/E2B) |
| **microsandbox** | microsandbox | Self-hosted microVM (libkrun) sandbox for untrusted AI/user code. Lightweight and locally deployable. | [github.com/microsandbox/microsandbox](https://github.com/microsandbox/microsandbox) |
| **OpenShell** | NVIDIA | Safe private runtime for autonomous AI agents. Sandboxed execution governed by declarative YAML policies preventing unauthorized file access, data exfiltration, and uncontrolled network activity. | [github.com/NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell) |
| **OpenSandbox** | Alibaba | Secure, fast, extensible sandbox runtime for AI agents. Multi-language SDKs, Docker/Kubernetes runtimes, gVisor/Kata Containers/Firecracker isolation. CNCF Landscape project. | [github.com/alibaba/OpenSandbox](https://github.com/alibaba/OpenSandbox) |
| **Aegis** | Antropos | Open-source EDR for AI agents. Monitors processes, files, network, and behavior of autonomous agents in real time. Local-only, no cloud telemetry. | [github.com/antropos17/Aegis](https://github.com/antropos17/Aegis) |
| **Microsoft Agent Governance Toolkit** | Microsoft | Policy enforcement, zero-trust identity, execution sandboxing, and reliability engineering for autonomous AI agents. Addresses all 10 OWASP Agentic Top 10 risks. | [github.com/microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit) |
| **agentfield** | Agent-Field | Open-source control plane for agent systems: cryptographic identity, policy enforcement, and audit-friendly observability. | [github.com/Agent-Field/agentfield](https://github.com/Agent-Field/agentfield) |
| **leash** | StrongDM | Wraps AI coding agents in containers and monitors their activity for anomalous behavior and policy violations. | [github.com/strongdm/leash](https://github.com/strongdm/leash) |
| **vibekit** | superagent-ai | Run Claude Code, Gemini, Codex, or any coding agent in an isolated sandbox with sensitive data redaction and observability. | [github.com/superagent-ai/vibekit](https://github.com/superagent-ai/vibekit) |
| **pipelock** | luckyPipewrench | Security harness for AI agents: egress proxy with DLP scanning, SSRF protection, MCP response scanning, and workspace integrity monitoring. | [github.com/luckyPipewrench/pipelock](https://github.com/luckyPipewrench/pipelock) |
| **skill-scanner** | Cisco AI Defense | Security scanner for AI agent skills. Detects prompt injection, data exfiltration, and malicious code using YAML+YARA patterns, LLM-as-judge, and behavioral dataflow analysis. | [github.com/cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) |
| **Project CodeGuard** | CoSAI / OASIS | Open-source security controls and guardrails for AI coding assistants to prevent vulnerabilities in AI-generated code. | [github.com/cosai-oasis/project-codeguard](https://github.com/cosai-oasis/project-codeguard) |
| **AgentLens** | Dreadnode | Agent observability and replay tooling. Captures trajectories in ATIF format, tracks file state changes across sessions. Built for studying multi-turn, multi-session, multi-agent behavior. | [github.com/dreadnode/agent-lens](https://github.com/dreadnode/agent-lens) |
| **OneCLI** | onecli | Rust HTTP gateway credential vault for AI agents. Intercepts requests and injects API keys transparently — agents never hold raw credentials. AES-256-GCM, per-agent scoped tokens, audit trail. | [github.com/onecli/onecli](https://github.com/onecli/onecli) |
| **SuperClaw** | SuperagenticAI | Pre-deployment security testing for autonomous AI coding agents. Tests prompt injection, privilege escalation, data exfiltration paths, and insecure code generation. Outputs HTML/JSON/SARIF (GitHub Code Scanning compatible). | [github.com/SuperagenticAI/superclaw](https://github.com/SuperagenticAI/superclaw) |

### MCP Security

| Tool | By | What It Does | Link |
|------|----|-------------|------|
| **mcp-context-protector** | Trail of Bits | Security wrapper for MCP servers addressing line jumping, unexpected server configuration changes, and prompt injection attacks from untrusted MCP servers. | [github.com/trailofbits/mcp-context-protector](https://github.com/trailofbits/mcp-context-protector) |
| **mcp-guardian** | eqtylab | Manages LLM assistant access to MCP servers with real-time control over agent activity. | [github.com/eqtylab/mcp-guardian](https://github.com/eqtylab/mcp-guardian) |
| **MCP Audit VSCode Extension** | Agentity | Audit and log all GitHub Copilot MCP tool calls in VSCode centrally. | [github.com/Agentity-com/mcp-audit-extension](https://github.com/Agentity-com/mcp-audit-extension) |
| **Awesome-MCP-Security** | Puliczek | Curated reference covering everything in the MCP security space: attacks, defenses, tools, CVEs. | [github.com/Puliczek/awesome-mcp-security](https://github.com/Puliczek/awesome-mcp-security) |

### AI Code Security

| Tool | By | What It Does | Link |
|------|----|-------------|------|
| **sec-context** | Arcanum-Sec | AI code security anti-patterns synthesized from 150+ sources. Two formats: breadth (~65K tokens, 25+ vulnerability patterns with BAD/GOOD examples) and depth (~100K tokens, deep dives on 7 highest-priority vulnerabilities). Inject into LLM system prompts to prevent AI coding assistants from generating vulnerable code. | [github.com/Arcanum-Sec/sec-context](https://github.com/Arcanum-Sec/sec-context) |
| **Vulnhuntr** | ProtectAI | LLM-powered vulnerability analysis. Traces multi-step code paths across Python codebases to find zero-day class vulnerabilities (LFI, SSRF, RCE, SQLi, XSS, IDOR) that standard SAST misses. | [github.com/protectai/vulnhuntr](https://github.com/protectai/vulnhuntr) |
| **CodeGate** | Stacklok | Self-hosted security gateway for AI code generation. Sits as proxy between IDE and AI provider: detects prompt injection, flags hardcoded secrets, filters malicious package suggestions. | [stacklok.com](https://stacklok.com/) |
| **Semgrep AI Best-Practices Rules** | Semgrep | 58 Semgrep Pro rules for detecting prompt injection risks, missing safety checks, hardcoded API keys in LLM code across 7 languages. Static analysis for CI pipelines. | [github.com/semgrep/ai-best-practices](https://github.com/semgrep/ai-best-practices) |
| **medusa** | Pantheon Security | AI-first security scanner with 74+ analyzers, 180+ AI agent security rules, and intelligent false positive reduction. Detects CVEs in React2Shell and mcp-remote RCE. Supports all major languages. | [github.com/Pantheon-Security/medusa](https://github.com/Pantheon-Security/medusa) |
| **claude-secure-coding-rules** | TikiTribe | Open-source security rules that guide Claude Code to generate secure code by default. Policy-driven coding assistant guardrails. | [github.com/TikiTribe/claude-secure-coding-rules](https://github.com/TikiTribe/claude-secure-coding-rules) |
| **claude-code-devcontainer** | Trail of Bits | Sandboxed devcontainer for running Claude Code in bypass mode safely. Built for security audits and untrusted code review. | [github.com/trailofbits/claude-code-devcontainer](https://github.com/trailofbits/claude-code-devcontainer) |

### Privacy-Preserving Inference

| Tool | By | What It Does | Link |
|------|----|-------------|------|
| **Concrete ML** | Zama | ML models using Fully Homomorphic Encryption (FHE). Supports scikit-learn, XGBoost, Random Forest, and neural networks. Client receives inference results without server seeing plaintext input. | [github.com/zama-ai/concrete-ml](https://github.com/zama-ai/concrete-ml) |
| **TensorFlow Privacy** | Google | Differential privacy algorithms for ML training. Implements DP-SGD and related privacy-preserving training techniques. | [github.com/tensorflow/privacy](https://github.com/tensorflow/privacy) |
| **OpenDP** | Harvard Privacy Tools / Microsoft Research | Framework-agnostic differential privacy algorithms. Laplace, Gaussian, exponential mechanisms, DP-SGD. Used in production at the US Census Bureau. | [github.com/opendp/opendp](https://github.com/opendp/opendp) |
| **PySyft** | OpenMined | Privacy-preserving ML framework: federated learning, differential privacy, secure multi-party computation. Reference framework for testing secure FL architectures. | [github.com/OpenMined/PySyft](https://github.com/OpenMined/PySyft) |

---

## 6. AI for Security Operations

*Tools that USE AI to perform security work. For tools that secure AI systems, see [Section 5](#5-tools--defense--detection).*

### Penetration Testing & Offensive Security

| Tool | By | What It Does | Link |
|------|----|-------------|------|
| **PentestGPT** | GreyDGL | Autonomous LLM-driven pentest agent for web, reversing, forensics, crypto, and privilege escalation. Peer-reviewed at USENIX Security 2024. Docker deployment with session persistence. | [github.com/GreyDGL/PentestGPT](https://github.com/GreyDGL/PentestGPT) |
| **PentAGI** | vxcontrol | Fully autonomous AI agent system for penetration testing. Multi-agent architecture: specialized subagents for recon, exploitation, and reporting. Web UI, Docker. | [github.com/vxcontrol/pentagi](https://github.com/vxcontrol/pentagi) |
| **CAI (Cybersecurity AI)** | Alias Robotics | Open-source agentic cybersecurity framework. 300+ supported AI models, purpose-built for CTFs and offensive security. Multiple arXiv publications on LLM performance in offensive security. | [github.com/aliasrobotics/cai](https://github.com/aliasrobotics/cai) |
| **HackingBuddyGPT** | TU Wien IPA-Lab | LLM-assisted Linux privilege escalation and web pentesting research framework. Published benchmarks comparing model performance on real privesc tasks. | [github.com/ipa-lab/hackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT) |
| **Nebula** | Beryllium Security | CLI pentest assistant integrating OpenAI, Llama, Mistral, and DeepSeek models into the terminal. Automates vulnerability assessment and engagement note-taking. | [github.com/berylliumsec/nebula](https://github.com/berylliumsec/nebula) |
| **Fabric** | Daniel Miessler | Pattern-based AI framework with pre-built security patterns: threat modeling, vulnerability analysis, CTI summarization. Runs locally against any LLM. | [github.com/danielmiessler/fabric](https://github.com/danielmiessler/fabric) |
| **shannon** | Keygraph | Fully autonomous AI pentester for web apps and APIs. White-box security testing — analyzes source code, identifies attack vectors, executes real exploits. 96.15% success rate (100/104 exploits) on XBOW benchmark. | [github.com/KeygraphHQ/shannon](https://github.com/KeygraphHQ/shannon) |
| **strix** | usestrix | Autonomous AI agents that act like real hackers: run code dynamically, find vulnerabilities, and validate them via actual proof-of-concept exploits. | [github.com/usestrix/strix](https://github.com/usestrix/strix) |
| **redamon** | samugit83 | AI-powered agentic red team framework. Automates offensive operations from reconnaissance through exploitation and post-exploitation with zero human intervention. | [github.com/samugit83/redamon](https://github.com/samugit83/redamon) |
| **burpgpt** | aress31 | Burp Suite extension integrating GPT for passive scanning. Discovers highly bespoke vulnerabilities through traffic-based analysis that rules-based scanners miss. | [github.com/aress31/burpgpt](https://github.com/aress31/burpgpt) |

### Malware Analysis & Reverse Engineering

| Tool | By | What It Does | Link |
|------|----|-------------|------|
| **Gepetto** | JusticeRage | IDA Pro plugin sending decompiled functions to LLMs (GPT-4o, Gemini, Claude, Ollama) for natural-language explanations and variable renaming. | [github.com/JusticeRage/Gepetto](https://github.com/JusticeRage/Gepetto) |
| **IDAssist** | symgraph | IDA Pro plugin with deeper LLM integration — explains functions, suggests renames, answers questions about binaries, builds a knowledge graph across an entire program. | [github.com/symgraph/IDAssist](https://github.com/symgraph/IDAssist) |
| **GhidrAssist** | symgraph | LLM extension for Ghidra. Integrates any OpenAI v1-compatible API for code explanation, interactive binary analysis, and automated vulnerability detection. | [github.com/symgraph/GhidrAssist](https://github.com/symgraph/GhidrAssist) |
| **LLM4Decompile** | albertan017 | Open-source LLMs (1.3B–22B) fine-tuned for decompiling Linux x86_64 binaries to C. Achieves up to 64.9% re-executability. Ghidra pseudo-code refinement variant included. | [github.com/albertan017/LLM4Decompile](https://github.com/albertan017/LLM4Decompile) |
| **GhidraGPT** | ZeroDaysBroker | Integrates GPT into Ghidra for automated code analysis, variable renaming, vulnerability detection, and explanation generation. | [github.com/ZeroDaysBroker/GhidraGPT](https://github.com/ZeroDaysBroker/GhidraGPT) |

### Vulnerability Research

| Tool | By | What It Does | Link |
|------|----|-------------|------|
| **Buttercup** | Trail of Bits | DARPA AIxCC submission — ML-assisted fuzzing for vulnerability discovery + multi-agent LLM patcher for automatically generating and applying security patches. | [github.com/trailofbits/buttercup](https://github.com/trailofbits/buttercup) |
| **Vulnhuntr** | ProtectAI | LLM-powered vulnerability analysis tracing full code call chains. Finds complex multi-file vulnerabilities (LFI, RCE, SSRF, SQLi, XSS, IDOR) that static analysis misses. | [github.com/protectai/vulnhuntr](https://github.com/protectai/vulnhuntr) |

### Threat Intelligence & SOC

| Tool | By | What It Does | Link |
|------|----|-------------|------|
| **OpenCTI** | Filigran | Open-source threat intelligence platform with AI-assisted analyst features: automatic entity extraction, relationship inference, enrichment from threat reports. Integrates with MISP, TheHive, MITRE ATT&CK. | [github.com/OpenCTI-Platform/opencti](https://github.com/OpenCTI-Platform/opencti) |
| **MISP** | CIRCL | Standard open-source threat intelligence and sharing platform. Relevant for AI/ML analysis integrations: MISP-STIX, PyMISP for LLM pipeline automation, community AI-powered enrichment modules. | [github.com/MISP/MISP](https://github.com/MISP/MISP) |
| **Elastic Security** | Elastic | Open-source SIEM/XDR with AI Assistant: natural-language query generation, alert explanation, automated incident investigation. Detection rules: Apache 2.0, publicly maintained. | [elastic.co/security](https://www.elastic.co/security) · [Detection rules](https://github.com/elastic/detection-rules) |
| **Wazuh** | Wazuh | Widely deployed open-source XDR/SIEM with ML-based anomaly detection, behavioral analysis, and AI-augmented alert triage. Fully self-hosted. | [github.com/wazuh/wazuh](https://github.com/wazuh/wazuh) |
| **ThreatForest** | AWS Samples | Agentic threat modeling platform built on the Strands framework. Autonomously generates attack trees from repositories, maps steps to MITRE ATT&CK, and produces actionable mitigation recommendations. | [github.com/aws-samples/sample-agentic-attack-tree-generator](https://github.com/aws-samples/sample-agentic-attack-tree-generator) |
| **claude-grc-plugin** | mlunato47 | Claude Code plugin for GRC work. 72+ reference files covering 15 frameworks (NIST 800-53, FedRAMP, ISO 27001, SOC 2), 24 slash commands, deep compliance domain knowledge. | [github.com/mlunato47/claude-grc-plugin](https://github.com/mlunato47/claude-grc-plugin) |
| **Vigil SOC** | Vigil-SOC | Open-source security operations platform for AI agents. Real-time monitoring, threat detection, and incident response for AI-powered environments. | [github.com/Vigil-SOC/vigil](https://github.com/Vigil-SOC/vigil) |

### Security-Specialized Models

| Model | By | What It Does | Link |
|-------|----|-------------|------|
| **Foundation-Sec-8B** | Fdtn.ai | 8B parameter LLM pretrained on cybersecurity corpora. Outperforms Llama 3.1 70B on CTI benchmarks at 10× fewer parameters. Use for threat intel synthesis, CTI report analysis, SOC text classification. | [huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct) |
| **Foundation-Sec-8B-Reasoning** | Fdtn.ai | Extended from Foundation-Sec-8B with instruction-following and chain-of-thought reasoning capabilities. Specialized for security analysis tasks requiring multi-step reasoning. | [huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning) |
| **VulnLLM-R-7B** | UCSB SURFI | 7B reasoning LLM for vulnerability detection. Uses Chain-of-Thought to analyze data flow, control flow, and security context. Outperforms Claude-3.7-Sonnet and CodeQL on vulnerability detection benchmarks. | [huggingface.co/UCSB-SURFI/VulnLLM-R-7B](https://huggingface.co/UCSB-SURFI/VulnLLM-R-7B) |

**Safety classifiers and prompt injection detectors:**

| Model | By | What It Does | Link |
|-------|----|-------------|------|
| **Llama-Guard-4-12B** | Meta | Latest multimodal safety classifier. Detects harmful content in LLM inputs and outputs across text and image modalities. | [huggingface.co/meta-llama/Llama-Guard-4-12B](https://huggingface.co/meta-llama/Llama-Guard-4-12B) |
| **Llama-Prompt-Guard-2-86M** | Meta | Lightweight 86M parameter model for detecting prompt injection and jailbreak attempts in production LLM pipelines. Low latency, high throughput. | [huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) |
| **ShieldGemma-2B** | Google | 2B parameter text safety classifier built on Gemma architecture for detecting harmful content in LLM pipelines. | [huggingface.co/google/shieldgemma-2b](https://huggingface.co/google/shieldgemma-2b) |
| **DeBERTa Prompt Injection Detector v2** | Protect AI | DeBERTa-v3-base fine-tuned for prompt injection detection. Widely deployed in production LLM guardrail pipelines. | [huggingface.co/protectai/deberta-v3-base-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) |
| **Prompt Injection Sentinel** | Qualifire | ModernBERT-large fine-tuned for prompt injection and jailbreak classification with low false-positive rate. | [huggingface.co/qualifire/prompt-injection-sentinel](https://huggingface.co/qualifire/prompt-injection-sentinel) |

---

## 7. Notable Incidents & CVEs

A timeline of publicly documented attacks, exploits, and real-world AI security incidents. Useful for threat modeling impact assessments, building case studies, and tracking the evolving threat landscape.

### 2026

| Date | Incident / CVE | What Happened | Source |
|------|---------------|---------------|--------|
| Mar 2026 | **LiteLLM TeamPCP Supply Chain Attack** | Threat actor compromised LiteLLM's CI/CD pipeline via a Trivy GitHub Action, stole PyPI credentials, and published backdoored versions 1.82.7–1.82.8 with multi-stage credential stealers harvesting API keys, SSH keys, cloud credentials, and crypto wallets. 3.4M daily downloads; live for ~3 hours. Part of a 5-day campaign also hitting Trivy (CVE-2026-33634), npm, and Checkmarx KICS. | [wiz.io](https://www.wiz.io/blog/threes-a-crowd-teampcp-trojanizes-litellm-in-continuation-of-campaign) / [datadoghq.com](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/) |
| Mar 2026 | **CVE-2026-26133 — Microsoft 365 Copilot XPIA** | Attacker embeds malicious instructions in a plain email; Copilot's summarization output is hijacked to produce convincing phishing content without any attachments or macros. Patched March 2026. | [cybersecuritynews.com](https://cybersecuritynews.com/microsoft-copilot-summarization-vulnerability/) |
| Mar 2026 | **Reprompt — Microsoft Copilot Session Exfiltration** | Single-link attack that bypasses Copilot's data-leak protections and enables persistent session exfiltration even after Copilot is closed. Discovered by Varonis. | [varonis.com/blog](https://www.varonis.com/blog/reprompt) |
| Mar 2026 | **CVE-2026-26144 — Excel + Copilot Zero-Click Exfiltration** | XSS flaw in Microsoft Excel chains with Copilot Agent mode to exfiltrate data via unintended network egress with zero user interaction required. Patched March 11, 2026. | [theregister.com](https://www.theregister.com/2026/03/10/zeroclick_microsoft_info_disclosure_bug/) |
| Mar 2026 | **CVE-2026-33017 — Langflow RCE** | Critical (CVSS 9.3) unauthenticated RCE in Langflow ≤1.8.1. Exploited in the wild within 20 hours of advisory, without any public PoC. Exfiltrated API keys enabled cloud lateral movement. | [thehackernews.com](https://thehackernews.com/2026/03/critical-langflow-flaw-cve-2026-33017.html) |
| Mar 2026 | **CVE-2026-27825 — mcp-atlassian** | Critical unauthenticated RCE and SSRF via path traversal in Confluence attachment download tools. Missing directory confinement enables arbitrary file write and local privilege escalation. | [arcticwolf.com](https://arcticwolf.com/resources/blog-uk/cve-2026-27825-critical-unauthenticated-rce-and-ssrf-in-mcp-atlassian/) |
| Mar 2026 | **CVE-2026-26118 — Azure MCP Server** | SSRF-based elevation of privilege in Azure MCP Server Tools via crafted input to user-parameter-accepting tools. March 2026 Patch Tuesday. | [msrc.microsoft.com](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2026-26118) |
| Mar 2026 | **IDEsaster — 30+ CVEs Across All Major AI Coding IDEs** | Researcher Ari Marzouk disclosed 24+ CVEs across Cursor, Windsurf, GitHub Copilot, Zed, Kiro.dev, Cline, and others. 100% of tested AI IDEs were vulnerable. Novel chain: Prompt Injection → IDE Tool Use → Base IDE Features (RCE, credential exfiltration). Affects millions of developers globally. | [thehackernews.com](https://thehackernews.com/2025/12/researchers-uncover-30-flaws-in-ai.html) |
| Feb 2026 | **RoguePilot — GitHub Copilot Passive Injection → Repo Takeover** | Malicious GitHub Issue triggers passive prompt injection in a Codespace; Copilot exfiltrates `GITHUB_TOKEN` via crafted JSON schema request to attacker server → full repository takeover. Discovered by Orca Security; patched by Microsoft. | [orca.security](https://orca.security/resources/blog/roguepilot-github-copilot-vulnerability/) |
| Feb 2026 | **Rules File Backdoor — Cursor & GitHub Copilot Supply Chain** | Attackers inject hidden Unicode characters into `.cursorrules` / Copilot configuration files to silently poison AI-generated code with backdoors that survive code review. | [pillar.security](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents) |
| Feb 2026 | **CVE-2026-25253 — OpenClaw Agent RCE** | Critical one-click RCE in OpenClaw (135,000+ GitHub stars). The Control UI trusted a `gatewayUrl` query parameter without validation, auto-connecting to attacker-specified URLs and transmitting stored auth tokens over WebSocket. 21,000+ exposed instances; 12% of ClawHub marketplace skills were malicious. First major AI agent security crisis of 2026; MITRE ATLAS mapped 7 new agent-specific TTPs. | [ctid.mitre.org](https://ctid.mitre.org/blog/2026/02/09/mitre-atlas-openclaw-investigation/) |
| Feb 2026 | **CVE-2026-25536 — MCP TypeScript SDK Cross-Client Data Leak** | SDK versions 1.10.0–1.25.3: one client may receive data intended for another when a single McpServer instance is reused across clients. | [vulnerablemcp.info](https://vulnerablemcp.info/) |
| Feb 2026 | **PROMPTFLUX / PROMPTSTEAL — AI-Native Malware** | Google GTIG documented first AI-native malware families. PROMPTFLUX uses an LLM during execution to dynamically generate malicious scripts; PROMPTSTEAL uses an LLM to obfuscate data exfiltration code in real time. State-backed adversaries (DPRK, Iran, China, Russia) operationalized AI across the full attack lifecycle in 2025. | [cloud.google.com](https://cloud.google.com/blog/topics/threat-intelligence/distillation-experimentation-integration-ai-adversarial-use) |
| Feb 2026 | **ToxicSkills — Agent Skills Malware Campaign** | 36% of ClawHub AI agent skills contained prompt injection; 76 confirmed malicious payloads for credential theft, backdoor installation, and data exfiltration. Three markdown lines sufficient to exfiltrate SSH keys. | [snyk.io](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) |
| Feb 2026 | **AI Recommendation Poisoning** | Microsoft Defender documented 50+ real-world cases of prompt injection poisoning AI assistant memory (ChatGPT, Copilot, Claude, Perplexity, Grok) for commercial promotion. 31 companies across 14 industries. | [microsoft.com/security/blog](https://www.microsoft.com/en-us/security/blog/2026/02/10/ai-recommendation-poisoning/) |
| Feb 2026 | **GreyNoise: 91K+ Sessions Targeting LLM Infrastructure** | 91,403 sessions targeting Ollama LLM inference servers over Oct 2025–Jan 2026. Single 11-day campaign tested 73+ model endpoints across GPT-4o, Claude, Llama, Gemini, Mistral, DeepSeek. | [greynoise.io](https://www.greynoise.io/blog/threat-actors-actively-targeting-llms) |
| Feb 2026 | **CVE-2026-21858 — n8n AI Workflow Platform RCE** | Critical unauthenticated RCE (CVSS 10.0) in n8n, a widely-deployed AI workflow automation platform. Allows internal file leakage and full platform takeover. | [csoonline.com](https://www.csoonline.com/article/4113980/critical-rce-flaw-allows-full-takeover-of-n8n-ai-workflow-platform.html) |
| Jan 2026 | **CVE-2025-59944 / CVE-2025-64106 — Cursor IDE** | Dual CVEs in Cursor IDE allowing privilege escalation via malicious workspace files and unsafe extension execution. Attack surface for AI coding assistant exploitation. | [research.checkpoint.com](https://research.checkpoint.com) |
| Jan 2026 | **CVE-2026-21852 — Claude Code API Key Exfiltration** | Malicious repo overrides `ANTHROPIC_BASE_URL` in `.claude/settings.json`; every Claude API call then sends the `Authorization` header to an attacker-controlled endpoint. | [research.checkpoint.com](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) |
| Jan 2026 | **CVE-2026-0628 — Gemini Chrome Panel Hijacking ("Glic Jack")** | Chrome WebView insufficient policy enforcement allows a low-privilege extension to inject code into Gemini Live's side panel and inherit file access, screenshot, and camera/microphone capabilities. CVSS 8.8. | [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/gemini-live-in-chrome-hijacking/) |
| Jan 2026 | **Operation Bizarre Bazaar — LLMjacking** | First attributed large-scale LLMjacking campaign with commercial monetization. 35,000 sessions targeting Ollama, OpenAI-compatible APIs, MCP servers. Stolen access resold at 40–60% discount. | [pillar.security](https://www.pillar.security/blog/operation-bizarre-bazaar-first-attributed-llmjacking-campaign-with-commercial-marketplace-monetization) |

### 2025

| Date | Incident / CVE | What Happened | Source |
|------|---------------|---------------|--------|
| 2025 | **GeminiJack — Google Gemini Zero-Click Enterprise Data Exfiltration** | Hidden instructions in a shared Google Doc, Calendar invite, or email caused Gemini Enterprise to silently exfiltrate Gmail, Calendar, and Docs data — no user clicks required. Discovered by Noma Labs; patched by Google after coordinated disclosure. | [noma.security](https://noma.security/blog/geminijack-google-gemini-zero-click-vulnerability/) |
| 2025 | **SesameOp — OpenAI Assistants API as Malware C2** | First confirmed real-world backdoor using a commercial AI API (OpenAI Assistants) as covert command-and-control. Discovered by Microsoft DART during live incident response; threat actor was present for months. Now documented as MITRE ATLAS case study AML.CS0042. | [microsoft.com/security/blog](https://www.microsoft.com/en-us/security/blog/2025/11/03/sesameop-novel-backdoor-uses-openai-assistants-api-for-command-and-control/) |
| 2025 | **CVE-2025-68665 / CVE-2025-68664 — LangChain Serialization Injection** | Injection via `lc` keys in `toJSON()` allows malicious LangChain object structures through `metadata` and `additional_kwargs` → secret extraction and unsafe class instantiation. Affects `@langchain/core` < 1.1.8. | [github.com/langchain-ai](https://github.com/langchain-ai/langchainjs/security/advisories/GHSA-r399-636x-v7f6) |
| 2025 | **EchoLeak — CVE-2025-32711** | Zero-click prompt injection in Microsoft 365 Copilot. Chains XPIA bypass + Markdown redaction bypass + auto-fetched image abuse to exfiltrate SharePoint/Teams/OneDrive data without user interaction. CVSS 9.3. | [arXiv:2509.10540](https://arxiv.org/abs/2509.10540) |
| 2025 | **CVE-2025-53773 — GitHub Copilot RCE** | Attacker-controlled code comments triggered GitHub Copilot to generate and execute malicious code. | [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2025-53773) |
| 2025 | **CVE-2025-6514 — mcp-remote RCE** | Arbitrary command execution via malicious MCP server URL. CVSS 9.6. | [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2025-6514) |
| 2025 | **CVE-2025-59536 — Claude Code RCE** | RCE via malicious Hook commands in `.claude/settings.json`. Commands execute automatically when an untrusted repository is opened. | [research.checkpoint.com](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) |
| 2025 | **GTG-2002 Threat Actor** | Claude Code weaponized to conduct automated attacks against 17+ organizations. | [anthropic.com](https://www-cdn.anthropic.com/b2a76c6f6992465c09a6f2fce282f6c0cea8c200.pdf) |
| 2025 | **SpAIware — ChatGPT Memory Poisoning** | Persistent memory injection in ChatGPT's memory feature. Malicious webpage instructions persist across future sessions. Discovered by Johann Rehberger. | [embracethered.com](https://embracethered.com) |
| 2025 | **CVE-2025-3248 — Langflow RCE** | Unauthenticated RCE in Langflow via code execution endpoint. CVSS 9.8. | [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2025-3248) |
| 2024 | **LeftoverLocals — CVE-2023-4969** | GPU memory side-channel allowing cross-process recovery of LLM inference outputs. Demonstrated against Apple, AMD, and Qualcomm GPUs. | [blog.trailofbits.com](https://blog.trailofbits.com/2024/01/16/leftoverlocals-listening-to-llm-responses-through-leaked-gpu-local-memory/) |

**Tracking resources:**

- [TalEliyahu Disclosed AI Vulnerabilities Tracker](https://github.com/TalEliyahu/Awesome-AI-Security#publicly-disclosed-vulnerabilities) — Named AI vulnerability tracker with CVEs, descriptions, and sources
- [Vulnerable MCP Project](https://vulnerablemcp.info/) — Live MCP ecosystem CVE database
- [ProtectAI Sightline](https://sightline.protectai.com/) — AI/ML infrastructure CVE tracker with PoC exploits
- [AI Incident Database](https://incidentdatabase.ai/) — Crowdsourced real-world AI failure database
- [AIAAIC Repository](https://www.aiaaic.org/aiaaic-repository) — AI incidents, controversies, and accountability failures

---

## 8. Attack Frameworks & Knowledge Bases

| Framework | Publisher | What It Covers | Link |
|-----------|-----------|----------------|------|
| **MITRE ATLAS** | MITRE | Adversarial Tactics, Techniques, and Case Studies for AI/ML. The ATT&CK equivalent for AI. Full attack lifecycle from reconnaissance to impact. v5.4.0 (Feb 2026): 16 tactics, 84 techniques, 32 mitigations, 42 case studies. Adds AI Agent Context Poisoning, AI Agent Clickbait (AML.T0100), Publish Poisoned AI Agent Tool, Escape to Host. New case study AML.CS0042 (SesameOp — OpenAI Assistants API as C2). OpenClaw investigation added 7 new agent-specific techniques. | [atlas.mitre.org](https://atlas.mitre.org/) |
| **ARC Prompt Injection Taxonomy** | Arcanum-Sec | The most structured open classification for prompt injection attacks. Four dimensions: attacker intent (13), execution technique (18), filter evasion (20), input surface. Interactive frontend. | [github.com/Arcanum-Sec/arc_pi_taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy) · [Live](https://arcanum-sec.github.io/arc_pi_taxonomy/) |
| **OWASP LLM Top 10 (2025)** | OWASP | Ten most critical risks in LLM applications. 2025 edition adds Vector/Embedding Weaknesses and System Prompt Leakage; rewrites Excessive Agency; renames DoS to Unbounded Consumption. | [genai.owasp.org/llm-top-10](https://genai.owasp.org/llm-top-10/) |
| **OWASP Top 10 for Agentic Applications (2026)** | OWASP | Dedicated top-10 risk list for agentic AI systems (ASI01–ASI10): Agent Goal Hijack, Rogue Agents, Excessive Agency, Insecure Tool Integration, Insufficient IAM, Cascading Failures/Memory Poisoning, Insecure Supply Chain, Data Leakage, Poisoned Data, Human-Agent Trust Exploitation. Developed with 100+ industry experts. | [genai.owasp.org](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) |
| **OWASP Non-Human Identities (NHI) Top 10** | OWASP | First OWASP list for machine/agent identity security risks: secret leakage, overprivileged NHI, long-lived secrets. Directly applicable to AI agent deployments. | [owasp.org/www-project-non-human-identities-top-10](https://owasp.org/www-project-non-human-identities-top-10/) |
| **OWASP Machine Learning Security Top 10** | OWASP | Classical ML risks beyond LLMs: input manipulation, data poisoning, model inversion, membership inference, model theft. | [owasp.org/www-project-machine-learning-security-top-10](https://owasp.org/www-project-machine-learning-security-top-10/) |
| **NIST AI 100-2 (Adversarial ML Taxonomy)** | NIST | Standardized vocabulary for adversarial ML: evasion, poisoning, extraction, and inference attacks. The reference for consistent AI threat modeling language. Free PDF. | [nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2023.pdf](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2023.pdf) |
| **NIST AI 600-1 (GenAI Profile)** | NIST | AI RMF profile for generative AI. Maps 12 GenAI-specific risk categories (CBRN uplift, confabulation, data privacy, intellectual property, etc.) to concrete GOVERN/MAP/MEASURE/MANAGE actions. | [airc.nist.gov/technical-reports](https://airc.nist.gov/technical-reports/) |
| **GenAI Attacks Matrix (TTPs.ai)** | Community | ATT&CK-style matrix for GenAI, copilot, and agentic application attacks. Complements MITRE ATLAS for modern GenAI-specific TTPs. | [ttps.ai/matrix.html](https://ttps.ai/matrix.html) |
| **OffsecML Playbook** | Community | Practitioner-maintained playbook of offensive TTPs against ML systems: model extraction, evasion, poisoning, agentic attacks. ATLAS catalogs the TTPs; OffsecML shows how to execute them. | [wiki.offsecml.com](https://wiki.offsecml.com) |
| **CSA Maestro** | Cloud Security Alliance | Agentic AI threat modeling framework defining layered architecture from Foundation Models up to Agent Ecosystem, with threat categories per layer. The only framework with a structured architecture model specifically for multi-agent systems. | [cloudsecurityalliance.org](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) |
| **AIDEFEND Framework** | Community | Interactive defensive countermeasures knowledge base. Maps mitigations to MITRE ATLAS, Maestro, and OWASP LLM risks. The offense-to-defense bridge. | [github.com/edward-playground/aidefense-framework](https://github.com/edward-playground/aidefense-framework) |
| **OWASP AI Exchange** | OWASP | Comprehensive, community-maintained AI security knowledge base. Synthesizes and cross-references all OWASP AI projects, mapped to MITRE ATLAS and NIST. | [owaspai.org](https://owaspai.org/) |
| **BIML LLM Architectural Risk Analysis** | Berryville Institute of ML | Rigorous independent analysis of LLM threat categories — 12 threat domains with detailed technical treatment. Research-grade complement to practitioner-facing threat lists. Free PDF. | [berryvilleiml.com/docs/BIML-LLM24.pdf](https://berryvilleiml.com/docs/BIML-LLM24.pdf) |
| **FS-ISAC Adversarial AI Taxonomy** | FS-ISAC AI Risk WG | GenAI-specific threat taxonomy from the financial sector. Covers hallucinations, prompt injection, multimodal threats, model theft, supply chain, deepfakes. Cross-mapped to NIST AI RMF, MITRE ATLAS, CWE, CAPEC, OWASP. | [fsisac.com](https://www.fsisac.com/hubfs/Knowledge/AI/FSISAC_Adversarial-AI-Framework-TaxonomyThreatLandscapeAndControlFrameworks.pdf) |
| **MCP Security TTPs Matrix** | Community | TTP matrix for MCP attacks: tool poisoning, path traversal, SSRF, prompt injection via tools, cross-server escalation. | [modelcontextprotocol-security.io/ttps](https://modelcontextprotocol-security.io/ttps/) |
| **CSA MCP Client Top 10** | Cloud Security Alliance | Top 10 security risks for MCP client implementations. | [modelcontextprotocol-security.io/top10/client](https://modelcontextprotocol-security.io/top10/client/) |
| **CSA MCP Server Top 10** | Cloud Security Alliance | Top 10 security risks for MCP server implementations. | [modelcontextprotocol-security.io/top10/server](https://modelcontextprotocol-security.io/top10/server/) |
| **CSA LLM Threats Taxonomy** | Cloud Security Alliance | GenAI-focused threat taxonomy covering hallucinations, prompt injection, multimodal threats, model theft, supply chain, and deepfakes. | [cloudsecurityalliance.org](https://cloudsecurityalliance.org/artifacts/csa-large-language-model-llm-threats-taxonomy) |
| **AI Incident Database** | Responsible AI Collaborative | Crowdsourced database of real-world AI system failures. Use for threat modeling impact assessments and building incident case studies. | [incidentdatabase.ai](https://incidentdatabase.ai/) |
| **Hugging Face Security Advisories** | Hugging Face | Active reporting of malicious models on the Hub: pickle exploits, trojans, supply chain threats as they're discovered. | [huggingface.co/docs/hub/security](https://huggingface.co/docs/hub/security) |
| **TalEliyahu Disclosed AI Vulnerabilities Tracker** | Tal Eliyahu | Curated, maintained table of named AI system vulnerabilities with CVEs, descriptions, and sources. Covers EchoLeak, MCPoison, RoguePilot, CurXecute, LangGrinch, BodySnatcher, and more. | [github.com/TalEliyahu/Awesome-AI-Security](https://github.com/TalEliyahu/Awesome-AI-Security#publicly-disclosed-vulnerabilities) |
| **ProtectAI Sightline** | ProtectAI | AI/ML supply chain vulnerability database. CVEs in MLOps infrastructure with remediation advice, Nuclei templates, PoC exploits. | [sightline.protectai.com](https://sightline.protectai.com/) |
| **AIAAIC Repository** | AIAAIC | Publicly maintained database of AI and algorithmic incidents, controversies, and accountability failures — broader than AIID. | [aiaaic.org/aiaaic-repository](https://www.aiaaic.org/aiaaic-repository) |

---

## 9. Defensive Frameworks & Standards

### Risk Management

| Framework | Publisher | What It Is | Link |
|-----------|-----------|-----------|------|
| **NIST AI RMF (v1.0 / v1.1)** | NIST | Primary U.S. standard for AI risk management. Four functions: GOVERN, MAP, MEASURE, MANAGE. De facto enterprise baseline. v1.1 updated March 2026 with expanded MEASURE function guidance covering performance metric selection, bias and fairness evaluation methodologies, and monitoring cadence recommendations. v1.1 is now the emerging documentation baseline for AI governance programs. | [nist.gov/itl/ai-risk-management-framework](https://www.nist.gov/itl/ai-risk-management-framework) |
| **International AI Safety Report 2026** | 100+ AI experts, 30+ countries | Second international report led by Yoshua Bengio. Synthesizes scientific evidence on general-purpose AI capabilities, emerging risks, and risk management. Sections on adversarial robustness, misuse potential, and safety evaluation limitations. Free PDF. | [internationalaisafetyreport.org](https://internationalaisafetyreport.org/publication/international-ai-safety-report-2026) · [arXiv:2602.21012](https://arxiv.org/abs/2602.21012) |
| **NIST AI RMF Playbook** | NIST | Companion implementation guide to the RMF. More actionable — maps each function to concrete suggested actions. | [airc.nist.gov/airmf-resources/playbook](https://airc.nist.gov/airmf-resources/playbook/) |
| **Google SAIF (Secure AI Framework)** | Google | Six core security controls mapped to 14 identified AI risks across the ML lifecycle. Free whitepaper and interactive risk explorer. | [saif.google](https://saif.google/) |
| **CSA AI Controls Matrix (AICM)** | Cloud Security Alliance | 243 control objectives across 18 domains. Simultaneously maps to ISO 42001, ISO 27001, and NIST AI RMF — the most comprehensive control crosswalk available. Free download. | [cloudsecurityalliance.org/artifacts/ai-controls-matrix](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix) |
| **NCSC Guidelines for Secure AI System Development** | UK NCSC + CISA + ASD + CCCS + NZNCSC | Joint guidelines from five national cybersecurity agencies covering secure design, development, deployment, and maintenance of AI systems. | [ncsc.gov.uk/collection/guidelines-secure-ai-system-development](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development) |
| **ENISA Multilayer Framework** | ENISA | EU cybersecurity agency's flagship AI security output. Maps controls to AI risks across infrastructure, model, and application layers. European counterpart to NIST AI RMF. | [enisa.europa.eu/publications/multilayer-framework-for-good-cybersecurity-practices-for-ai](https://www.enisa.europa.eu/publications/multilayer-framework-for-good-cybersecurity-practices-for-ai) |
| **ISO/IEC 42001:2023** | ISO | International standard for AI Management Systems. Annex SL structure aligns to ISO 27001 and ISO 9001. Standard is paid; crosswalk resources exist free. | [iso.org/standard/81230.html](https://www.iso.org/standard/81230.html) |
| **BSI AIC4** | BSI (Germany) | Germany's criteria catalogue for auditing AI cloud services. The only publicly available certification catalogue specifically for AI cloud services. | [bsi.bund.de](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/CloudComputing/AIC4/AI-Cloud-Service-Compliance-Criteria-Catalogue_AIC4.pdf) |
| **NIST SP 800-218A (SSDF for GenAI)** | NIST | Secure Software Development Framework profile for generative AI. Maps SSDF practices to GenAI development risks. | [nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf) |
| **CISA/NSA Joint Advisory: Deploying AI Systems Securely** | CISA, NSA + allies | Practical hardening guidance for AI deployment: supply chain, model security, inference infrastructure. | [cisa.gov/news-events/alerts/2024/04/15/joint-guidance-deploying-ai-systems-securely](https://www.cisa.gov/news-events/alerts/2024/04/15/joint-guidance-deploying-ai-systems-securely) |
| **OWASP AIMA (AI Maturity Assessment)** | OWASP | Organizational maturity model for AI security. Self-assessment instrument with downloadable Excel toolkit. | [github.com/OWASP/www-project-ai-maturity-assessment](https://github.com/OWASP/www-project-ai-maturity-assessment) |
| **NIST AI Agent Standards Initiative** | NIST CAISI | Launched February 2026 to ensure autonomous AI agents are adopted securely and interoperably. Three pillars: industry-led agent standards, open protocol development, AI agent security and identity research. Listening sessions on sector-specific barriers begin April 2026. | [nist.gov](https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure) |
| **CISA/NSA Joint Guide — AI in Operational Technology** | CISA, NSA + allies | Published jointly with Australia, Canada, Germany, Netherlands, NZ, UK. Four principles for secure AI integration in OT/critical infrastructure environments: Understand AI, Assess AI Use in OT, Establish AI Governance, Embed Safety and Security. | [cisa.gov](https://www.cisa.gov/resources-tools/resources/principles-secure-integration-artificial-intelligence-operational-technology) |
| **MITRE SAFE-AI** | MITRE | Threat-informed RMF overlay for AI systems. Maps MITRE ATLAS tactics to NIST SP 800-53 controls, lists ~100 AI-affected controls, includes assessor interview Q&A sets for security control assessments (SCAs). | [compliancehub.wiki](https://www.compliancehub.wiki/content/files/2025/07/mitresafeAI.pdf) |
| **AI Security Shared Responsibility Model** | mikeprivette | Defines the shared security responsibilities between AI providers and AI consumers across the stack. Complements cloud shared responsibility models with AI-specific layers. | [github.com/mikeprivette/ai-security-shared-responsibility](https://github.com/mikeprivette/ai-security-shared-responsibility) |
| **BSI Security of AI Systems: Fundamentals** | BSI (Germany) | Sector-agnostic AI security fundamentals. Covers lifecycle threat model (data/model/pipeline/runtime), adversarial ML attacks, and baseline controls for design through operation with assurance guidance. Free PDF. | [bsi.bund.de](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/KI/Security-of-AI-systems_fundamentals.pdf) |
| **SANS Critical AI Security Guidelines** | SANS Community | Control-focused guidance for securing AI/LLM systems across six domains: access controls, data protection, inference security, monitoring, GRC. | [github.com/sans-community/ai-guidelines](https://github.com/sans-community/ai-guidelines) |
| **DoD CIO AI Cybersecurity Risk Management Tailoring Guide (2025)** | DoD CIO | Practical RMF tailoring for AI systems across the full lifecycle. Complements the DoD CDAO RAI Toolkit. | [dodcio.defense.gov](https://dodcio.defense.gov/Portals/0/Documents/Library/AI-CybersecurityRMTailoringGuide.pdf) |
| **NISTIR 8596 — Cybersecurity AI Profile (Preliminary Draft)** | NIST | Extends CSF 2.0 to AI-specific cybersecurity risks. Three pillars: Secure AI systems, Defend using AI to enhance security operations, Thwart AI-enabled attacks. Preliminary draft released Dec 2025; comment period closed Jan 2026. Full publication expected 2026. | [nvlpubs.nist.gov](https://nvlpubs.nist.gov/nistpubs/ir/2025/NIST.IR.8596.iprd.pdf) |
| **C2PA (Coalition for Content Provenance and Authenticity)** | C2PA (Adobe, Microsoft, Intel, BBC, Sony, Truepic) | Open technical standard for cryptographically binding provenance metadata to media files. Enables verification of origin and whether content has been altered. Adopted by major AI image generators (Adobe Firefly, DALL-E 3) and camera manufacturers. The verification layer for synthetic media incidents and deepfake IR. | [c2pa.org](https://c2pa.org/) |
| **NIST AI 100-4: Reducing Risks Posed by Synthetic Content** | NIST | Companion to the AI RMF addressing risks from AI-generated synthetic content: deepfakes, voice cloning, synthetic text, and AI-generated disinformation. Covers detection approaches, provenance standards (C2PA), and policy considerations. Free PDF. | [nvlpubs.nist.gov](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-4.pdf) |

### Verification Standards

| Standard | Publisher | What It Is | Link |
|----------|-----------|-----------|------|
| **OWASP LLMSVS** | OWASP | Security requirements checklist for LLM-based applications, organized by verification level (L1–L3). | [github.com/OWASP/www-project-llm-verification-standard](https://github.com/OWASP/www-project-llm-verification-standard) |
| **OWASP AISVS** | OWASP | Broader than LLMSVS — covers AI systems beyond LLMs. Maps to NIST AI RMF, OWASP Top 10s, and ISO 42001. | [github.com/OWASP/AISVS](https://github.com/OWASP/AISVS) |
| **OWASP LLM Applications Governance Checklist** | OWASP | Per-control implementation checklist for DevSecOps and governance teams. Distinct from the Top 10 (a risk list) and AISVS (a verification standard). | [genai.owasp.org](https://genai.owasp.org/resource/llm-applications-cybersecurity-and-governance-checklist-english/) |
| **OWASP Threat & Defense Compass** | OWASP | Maps GenAI risks to concrete mitigations with a runbook for design reviews. Bridges risk identification and control selection. | [genai.owasp.org](https://genai.owasp.org/resource/owasp-genai-security-project-threat-defense-compass-1-0/) |
| **OWASP AI Vulnerability Scoring System (AIVSS)** | OWASP | Scoring framework specifically designed for AI/ML vulnerabilities — extends CVSS with AI-specific dimensions like model sensitivity, training data exposure, and attack transferability. | [github.com/OWASP/www-project-artificial-intelligence-vulnerability-scoring-system](https://github.com/OWASP/www-project-artificial-intelligence-vulnerability-scoring-system) |
| **OWASP LLM Exploit Generation** | OWASP | Practical guidance and examples for constructing exploits against LLM applications across the OWASP LLM Top 10 categories. | [genai.owasp.org](https://genai.owasp.org/resource/owasp-llm-exploit-generation-v1-0-pdf/) |
| **OWASP AI Testing Guide** | OWASP | Comprehensive, structured methodologies and best practices for testing AI systems across the full testing lifecycle. | [github.com/OWASP/www-project-ai-testing-guide](https://github.com/OWASP/www-project-ai-testing-guide) |
| **CSA Secure LLM Systems: Authorization Practices** | Cloud Security Alliance | Essential authorization practices for securing LLM-backed systems: access control patterns, privilege boundaries, and identity management for LLM deployments. | [cloudsecurityalliance.org](https://cloudsecurityalliance.org/artifacts/securing-llm-backed-systems-essential-authorization-practices) |
| **MLSecOps Top 10** | Institute for Ethical AI & ML | Ten most critical risks in ML operations pipelines: covers the full ML lifecycle from data collection through deployment and monitoring. | [ethical.institute/security.html](https://ethical.institute/security.html) |
| **OWASP GenAI Data Security Risks & Mitigations (v1.0, 2026)** | OWASP | Released March 19, 2026. 21 risk categories (DSGAI01–DSGAI21) covering training datasets, prompts, and model outputs. Each risk includes attacker capability profiles, real-world CVEs, and tiered mitigations. | [genai.owasp.org](https://genai.owasp.org/resource/owasp-genai-data-security-risks-mitigations-2026/) |

### Threat Modeling

| Guide | Publisher | What It Covers | Link |
|-------|-----------|----------------|------|
| **OWASP Multi-Agentic System Threat Modeling Guide** | OWASP | Trust boundaries, tool permissions, memory poisoning, cross-agent attack flows in multi-agent systems. | [genai.owasp.org](https://genai.owasp.org/resource/multi-agentic-system-threat-modeling-guide-v1-0/) |
| **CSA Agentic AI Red Teaming Guide** | Cloud Security Alliance | Red teaming specifically for agentic AI: multi-agent trust chains, tool misuse, goal hijacking. | [cloudsecurityalliance.org](https://cloudsecurityalliance.org/artifacts/agentic-ai-red-teaming-guide) |
| **OWASP GenAI Red Teaming Guide** | OWASP | Step-by-step methodology for red team engagements against GenAI applications: scope, threat categorization, test case design, reporting. | [genai.owasp.org](https://genai.owasp.org/resource/genai-red-teaming-guide/) |
| **PLOT4ai** | Community | AI threat modeling library with 138 threats across 8 domains: Data, Privacy, Bias, Safety, Cybersecurity, Ethics, Transparency, Accountability. | [plot4.ai](https://plot4.ai/) |
| **Microsoft: Threat Modeling AI/ML Systems** | Microsoft | Applies SDL threat modeling to ML pipelines and AI components. | [learn.microsoft.com](https://learn.microsoft.com/en-us/security/engineering/threat-modeling-aiml) |
| **OWASP Agentic AI Threats and Mitigations** | OWASP | Threat and mitigation reference for agentic systems. Distinct from the Agentic Top 10 (prioritized risk list). | [genai.owasp.org](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/) |
| **OWASP Agent Name Service (ANS)** | OWASP | Secure naming, identity, and discovery for AI agents. Defines agent identification and authentication to prevent impersonation. | [genai.owasp.org](https://genai.owasp.org/resource/agent-name-service-ans-for-secure-al-agent-discovery-v1-0/) |
| **OWASP Agent Observability Standard (AOS)** | OWASP | Defines telemetry, logging, and traceability signals AI agents must expose to enable security monitoring. | [aos.owasp.org](https://aos.owasp.org/) |
| **A2A (Agent2Agent Protocol)** | Linux Foundation | Open specification for inter-agent communication, capability discovery, and task delegation. Defines how agents authenticate, exchange messages securely, and delegate subtasks. Originally developed by Google, now under Linux Foundation governance. | [a2a-protocol.org](https://a2a-protocol.org/latest/) |

### Incident Response

| Resource | Publisher | What It Covers | Link |
|----------|-----------|----------------|------|
| **OWASP GenAI Incident Response Guide** | OWASP | Practical IR guide for AI/LLM-specific incidents. Covers detection, containment, eradication, and recovery for prompt injection attacks, data poisoning, and model failures. | [genai.owasp.org](https://genai.owasp.org/resource/genai-incident-response-guide-1-0/) |
| **OWASP Guide for Preparing & Responding to Deepfake Events** | OWASP | Deepfake-specific IR guide covering detection, organizational preparation, and response playbooks for AI-generated synthetic media attacks (fraud, impersonation, disinformation). Distinct from the general GenAI IR guide. | [genai.owasp.org](https://genai.owasp.org/resource/guide-for-preparing-and-responding-to-deepfake-events/) |
| **CISA JCDC AI Cybersecurity Collaboration Playbook** | CISA | Federal guidance on AI incident response and coordination across critical infrastructure sectors. | [cisa.gov/artificial-intelligence](https://www.cisa.gov/artificial-intelligence) |

---

## 10. Regulatory & Compliance

### Compliance Deadline Timeline

| Deadline | Regulation | What Triggers |
|----------|-----------|---------------|
| Aug 2027 | EU AI Act | Full framework including all transitional provisions |
| Aug 2026 | EU AI Act | Annex III high-risk AI full compliance (**watch**: Digital Omnibus proposal could delay to Dec 2027 — EP IMCO/LIBE voted 101–9 in favour of delay Mar 2026; legislative process ongoing) |
| 2026 (watch) | Brazil AI Bill 2338/2023 | In legislative process |
| Jan 2026 | South Korea AI Basic Act | High-impact AI systems covered |
| Aug 2025 | EU AI Act | GPAI model obligations in force |
| Feb 2025 | EU AI Act | Prohibited AI systems banned (unacceptable risk tier) |
| Jul 2023 | NYC Local Law 144 | In force — bias audits for automated employment decision tools |
| Aug 2023 | China Generative AI Interim Measures | In force — applies to GenAI services serving users in China |
| No date set | Canada federal AI law | AIDA died Jan 2025; no replacement tabled as of early 2026 |

### EU AI Act (Regulation 2024/1689)

Risk-tiered: Unacceptable (banned) → High-Risk → Limited-Risk → Minimal Risk.

Key articles for security practitioners:

| Article | Requirement |
|---------|------------|
| Art. 9 | Risk management system — continuous, documented, per system |
| Art. 10 | Data governance — training data quality, bias examination |
| Art. 11 | Technical documentation — per-system, before market placement |
| Art. 12 | Logging — automatic, tamper-evident |
| Art. 13 | Transparency — interpretable outputs |
| Art. 14 | Human oversight — kill switch required for high-risk |
| Art. 15 | Accuracy, robustness, cybersecurity |
| Art. 72 | Post-market monitoring |
| Art. 73 | Incident reporting — 2 days (critical infrastructure), 10 days (death), 15 days (other serious) |

Full text: [eur-lex.europa.eu](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689)

### Key Regulatory References

| Jurisdiction | Resource | Link |
|-------------|---------|------|
| **United States — Federal** | CISA AI Security Guidance | [cisa.gov/artificial-intelligence](https://www.cisa.gov/artificial-intelligence) |
| **United States — State tracker** | NCSL AI Legislation Tracker — state-by-state bill status | [ncsl.org](https://www.ncsl.org/technology-and-communication/artificial-intelligence-2024-legislation) |
| **United States — Healthcare** | FDA AI/ML SaMD (Jan 2025 draft guidance) | [fda.gov](https://www.fda.gov/medical-devices/software-medical-device-samd/artificial-intelligence-software-medical-device) |
| **United States — Financial** | SR 11-7 Model Risk Management | [federalreserve.gov](https://www.federalreserve.gov/supervisionreg/srletters/sr1107.htm) |
| **United Kingdom** | ICO AI & Data Protection guidance | [ico.org.uk](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/artificial-intelligence/guidance-on-ai-and-data-protection/) |
| **Singapore** | Model AI Governance Framework — Agentic AI Edition (Jan 2026) | [imda.gov.sg](https://www.imda.gov.sg/-/media/imda/files/about/emerging-tech-and-research/artificial-intelligence/mgf-for-agentic-ai.pdf) |
| **China** | Interim Measures for Generative AI Services | [chinalawtranslate.com](https://www.chinalawtranslate.com/en/generative-ai-interim/) |
| **South Korea** | AI Basic Act — Framework Act on AI Development (enacted Jan 2025, in force Jan 2026) | [cset.georgetown.edu](https://cset.georgetown.edu/publication/south-korea-ai-law-2025/) |
| **Japan** | METI AI Guidelines for Business (Ver 1.01, Dec 2024) | [meti.go.jp](https://www.meti.go.jp/english/press/2024/0419_002.html) |
| **Australia** | Voluntary AI Safety Standard (Aug 2024) — 10 guardrails | [industry.gov.au](https://www.industry.gov.au/publications/voluntary-ai-safety-standard) |
| **India** | Digital Personal Data Protection Act (DPDPA) 2023 | [meity.gov.in](https://www.meity.gov.in/content/digital-personal-data-protection-act-2023) |

---

## 11. Community & Practice

### Communities & Organizations

| Community | Focus | Link |
|-----------|-------|------|
| **AI Village** | Primary community for offensive AI security. Runs talks, CTFs, and red teaming events at DEF CON. | [aivillage.org/events](https://aivillage.org/events/) · [X](https://x.com/aivillage_dc) · [Discord](https://discord.com/invite/GX5fhfT) |
| **OWASP GenAI Security Project** | Active working group behind the LLM Top 10, Agentic Top 10, LLMSVS, and related OWASP AI projects. | [genai.owasp.org](https://genai.owasp.org/) |
| **CoSAI (Coalition for Secure AI)** | OASIS Open Project. Four workstreams: AI supply chain security, defending AI systems, AI risk governance, secure agentic system design. | [github.com/cosai-oasis](https://github.com/cosai-oasis) |
| **OpenSSF AI/ML Security WG** | Linux Foundation / OpenSSF. Secure AI/ML supply chain, model signing, dependency security. | [github.com/ossf/ai-ml-security](https://github.com/ossf/ai-ml-security) |
| **CWE AI Working Group** | MITRE. Develops CWE classifications for AI-specific weaknesses. | [cwe.mitre.org/community/working_groups.html](https://cwe.mitre.org/community/working_groups.html) |
| **METR (Model Evaluation & Threat Research)** | Research nonprofit evaluating frontier AI models for autonomous capabilities and catastrophic risk. Standard methodology for autonomous AI risk assessment. | [metr.org](https://metr.org/) |
| **ENISA** | EU cybersecurity agency. Publishes annual AI threat landscape reports and sector-specific AI risk assessments. Free annual reports. | [enisa.europa.eu/topics/artificial-intelligence-and-next-gen-technologies](https://www.enisa.europa.eu/topics/artificial-intelligence-and-next-gen-technologies) |
| **CSET (Georgetown)** | Policy research on AI security, AI in national security contexts, and AI governance. | [cset.georgetown.edu](https://cset.georgetown.edu/) |
| **Partnership on AI** | Maintains the AI Incident Database. Conducts research on responsible AI deployment and publishes practitioner-facing guidance. | [partnershiponai.org](https://partnershiponai.org/) |

### Key Practitioners to Follow

Researchers with consistent, high-signal output on AI security:

| Researcher | Focus | Where |
|-----------|-------|-------|
| **Simon Willison** | Coined "prompt injection"; most prolific writer on indirect injection and multi-agent trust failures | [simonwillison.net/tags/prompt-injection](https://simonwillison.net/tags/prompt-injection/) |
| **Johann Rehberger** | Discovered SpAIware, Copilot data exfiltration chains; ran "Month of AI Bugs" documenting coding agent CVEs | [embracethered.com](https://embracethered.com) |
| **Nicholas Carlini** | Foundational training data extraction, membership inference, adversarial ML research (Anthropic / Google) | [nicholas.carlini.com](https://nicholas.carlini.com) |
| **Riley Goodside** | First to publicly demonstrate prompt injection (2022); discovered Unicode tag injection and novel jailbreaks | [@goodside](https://x.com/goodside) |
| **Tal Eliyahu** | Maintains Disclosed AI Vulnerabilities Tracker; publishes monthly AI Security Newsletter | [github.com/TalEliyahu](https://github.com/TalEliyahu/Awesome-AI-Security) |

### Conferences & Venues

| Conference | AI Security Focus | Link |
|-----------|-----------------|------|
| **DEF CON — AI Village** | Primary offensive AI security venue. Annual, August. YouTube archive of all past talks. | [aivillage.org/events](https://aivillage.org/events/) |
| **Black Hat** | AI and ML security tracks, adversarial ML, LLM security, AI infrastructure attacks. AI Summit added 2025. | [blackhat.com](https://www.blackhat.com/) |
| **IEEE SaTML** | Premier standalone academic conference dedicated to ML security and trustworthiness. Annual. | [satml.org](https://satml.org/) |
| **USENIX Security** | Strong ML security and privacy research. Full proceedings and video free online. | [usenix.org/conferences](https://www.usenix.org/conferences) |
| **CAMLIS** | Applied ML-for-security practitioner conference. Operational focus. Annual. | [camlis.org](https://www.camlis.org/) |
| **NeurIPS — AdvML-Frontiers Workshop** | Annual workshop on adversarial ML and large multimodal model security: adversarial robustness, jailbreak defenses, backdoor attacks, watermarking, poisoning. Proceedings free on OpenReview. | [neurips.cc](https://neurips.cc/virtual/2024/workshop/84707) |

### Bug Bounty Programs

**Open-source AI/ML — [Huntr](https://huntr.com/)** (ProtectAI): The primary bug bounty platform for AI/ML open-source projects. Reports go to maintainers of NumPy, scikit-learn, Hugging Face Transformers, and others. Purpose-built for AI/ML vulnerability classes: deserialization, supply chain, model loading bugs.

**Corporate programs:**

| Company | Scope | Link |
|---------|-------|------|
| **Anthropic** | Claude models, API, safety systems | [anthropic.com/responsible-disclosure-policy](https://www.anthropic.com/responsible-disclosure-policy) |
| **OpenAI** | GPT models, API, safety features | [openai.com/security](https://openai.com/security) |
| **Google** | Gemini, Vertex AI, AI products | [bughunters.google.com](https://bughunters.google.com/) |
| **Mozilla 0din.ai** | GenAI-specific program: prompt injection, model extraction, safety bypass across multiple AI providers | [0din.ai](https://0din.ai/) |

### Research Blogs Worth Following

Consistently high-signal AI security research output:

| Blog | Focus | Link |
|------|-------|------|
| **Trail of Bits** | ML model security, MCP/agentic attacks, AI audit methodology, GPU side-channels | [blog.trailofbits.com](https://blog.trailofbits.com/categories/machine-learning/) |
| **Johann Rehberger / Embrace the Writ** | Prompt injection CVEs, SpAIware, memory poisoning, "Month of AI Bugs" | [embracethered.com](https://embracethered.com) |
| **Palo Alto Unit 42** | LLM jailbreaks, bad Likert judge, MCP attacks, AI in threat operations | [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/) |
| **Wiz Research** | AI cloud infrastructure attacks, AI supply chain, offensive AI benchmarks | [wiz.io/blog](https://www.wiz.io/blog/) |
| **Microsoft Security Blog** | AI agent security, AI SDL, AI incident response, threat actor AI use | [microsoft.com/en-us/security/blog](https://www.microsoft.com/en-us/security/blog/) |
| **Invariant Labs** | MCP security, agent trace analysis, tool poisoning | [invariantlabs.ai/research](https://invariantlabs.ai/research) |
| **Anthropic Research** | Jailbreak defenses (Constitutional Classifiers), sleeper agents, many-shot, red teaming | [anthropic.com/research](https://www.anthropic.com/research) |
| **Google Project Zero / DeepMind** | Big Sleep (AI-discovered zero-days), AI-assisted vulnerability research | [projectzero.google](https://projectzero.google) |
| **Check Point Research** | AI coding assistant CVEs, supply chain vulnerabilities | [research.checkpoint.com](https://research.checkpoint.com/) |
| **Pillar Security** | LLMjacking, AI runtime threats, agentic security posture | [pillar.security/blog](https://www.pillar.security/blog) |
| **NCC Group Research** | AI threat modeling methodology, agentic architecture security, edge AI hardware | [research.nccgroup.com](https://research.nccgroup.com/) |
| **GreyNoise** | Internet-scale LLM infrastructure scanning, mass exploitation tracking | [greynoise.io/blog](https://www.greynoise.io/blog) |
| **8kSec** | AI/ML and mobile security research blog | [8ksec.io/blog](https://8ksec.io/blog/) |

### Newsletters & Podcasts

| Resource | Focus | Link |
|----------|-------|------|
| **tl;dr sec** | Weekly security newsletter with strong AI/ML coverage. Curated technical content: new research, tool releases, offensive AI, LLM security papers. Free. | [tldrsec.com](https://tldrsec.com/) |
| **MLSecOps Podcast** | Operationalizing ML security: securing training pipelines, ML security programs, red team and monitoring practices. | [mlsecops.com/podcast](https://mlsecops.com/podcast) |
| **AI Security Ops (Black Hills IS)** | Weekly podcast from BHIS on AI security threats and defensive tooling for practitioners. | [aisecurityops.transistor.fm](https://aisecurityops.transistor.fm) |
| **AI Security Podcast** | Independent practitioner podcast on AI security threats, defenses, and the evolving landscape. | [aisecuritypodcast.com](https://www.aisecuritypodcast.com/) |
| **GenAI Security Podcast** | Focused coverage on GenAI security: agentic risks, MCP, guardrails, red teaming. | [podcasts.apple.com](https://podcasts.apple.com/ph/podcast/the-genai-security-podcast/id1782916580) |
| **Adversarial AI Digest** | LinkedIn newsletter on AI security research, threats, governance challenges, and best practices. | [linkedin.com/newsletters](https://www.linkedin.com/newsletters/adversarial-ai-digest-7298813894498598912/) |

---

## Datasets

AI security–relevant datasets for training, evaluation, and red teaming.

### Safety & Attack Datasets

| Dataset | What It Contains | Link |
|---------|-----------------|------|
| **SafetyPrompts** | Living index of LLM safety datasets and evals: jailbreaks, prompt injection, toxicity, privacy. Filterable and maintained. | [safetyprompts.com](https://safetyprompts.com/) |
| **Do-Not-Answer** | Prompts that responsible LLMs should refuse to answer. Used for safety evaluation and red team coverage. | [github.com/Libr-AI/do-not-answer](https://github.com/Libr-AI/do-not-answer) |
| **JailBreakV-28K** | 28,000 jailbreak prompts across multiple categories for benchmarking LLM safety. Large-scale structured collection. | [github.com/SaFoLab-WISC/JailBreakV_28K](https://github.com/SaFoLab-WISC/JailBreakV_28K) |
| **Leaked System Prompts** | Collection of leaked system prompts from commercial AI tools. Useful for understanding real-world prompt engineering patterns and attack surfaces. | [github.com/x1xhlol/system-prompts-and-models-of-ai-tools](https://github.com/x1xhlol/system-prompts-and-models-of-ai-tools) |
| **JailbreakBench Dataset** | Standardized jailbreak test set with fixed behaviors and model responses. NeurIPS 2024. | [github.com/JailbreakBench/jailbreakbench](https://github.com/JailbreakBench/jailbreakbench) |

### Cybersecurity Skill Benchmarks

CTF challenge datasets for evaluating AI agents' offensive security capabilities.

| Dataset | What It Contains | Link |
|---------|-----------------|------|
| **InterCode-CTF** | 100 picoCTF challenges (crypto, web, pwn, RE, forensics). NLP+code interaction benchmark. [arXiv:2306.14898](https://arxiv.org/abs/2306.14898) | [github.com/princeton-nlp/intercode](https://github.com/princeton-nlp/intercode) |
| **NYU CTF Bench** | 200 CSAW challenges (2017–2023). Very easy to hard difficulty. [arXiv:2406.05590](https://arxiv.org/abs/2406.05590) | [github.com/NYU-LLM-CTF/NYU_CTF_Bench](https://github.com/NYU-LLM-CTF/NYU_CTF_Bench) |
| **CyBench** | 40 tasks from HackTheBox, Sekai CTF, Glacier, HKCert. Grounded by first-solve time. [arXiv:2408.08926](https://arxiv.org/abs/2408.08926) | [github.com/andyzorigin/cybench](https://github.com/andyzorigin/cybench) |
| **HackingBuddyGPT Benchmark** | Benchmark dataset for automated Linux privesc and web pentesting evaluation. | [github.com/ipa-lab/hacking-benchmark](https://github.com/ipa-lab/hacking-benchmark) |

---

## Agentic AI Security Skills

Skills (plugins) for AI coding assistants (Claude Code, Gemini CLI, Cursor, Copilot) that add security capabilities — scanning, threat modeling, vulnerability detection, and audit workflows.

| Skill | By | What It Adds | Link |
|-------|----|-------------|------|
| **Trail of Bits Security Skills** | Trail of Bits | Skills for security research, vulnerability detection, and audit workflows in Claude Code. | [github.com/trailofbits/skills](https://github.com/trailofbits/skills) |
| **Ghost Security AppSec Skills** | Ghost Security | Agent application security skills and tools for Claude Code: SAST, dependency analysis, web app security testing. | [github.com/ghostsecurity/skills](https://github.com/ghostsecurity/skills) |
| **Semgrep Skills** | Semgrep | Official Semgrep skills: security scanning, code analysis, vulnerability detection in AI-assisted development. Integrates with Claude Code and other AI coding assistants. | [github.com/semgrep/skills](https://github.com/semgrep/skills) |
| **Continuous Threat Modeling Skills** | izar | Agent skills for continuous threat modeling workflows using AI assistants. | [github.com/izar/tm_skills](https://github.com/izar/tm_skills) |
| **Anthropic Cybersecurity Skills** | mukul975 | 734+ structured cybersecurity skills for AI agents. MITRE ATT&CK mapped, compatible with Claude Code, Copilot, Codex CLI, Cursor, and Gemini CLI. | [github.com/mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) |
| **claude-bug-bounty** | shuvonsec | Claude Code skill for AI-assisted bug bounty hunting. Automates recon, IDOR, XSS, SSRF, OAuth, GraphQL, and LLM injection testing with 4-gate validation checklist and report generation. | [github.com/shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) |

---

*Contributions welcome. If you know of a paper, tool, or talk that belongs here, open a PR.*
