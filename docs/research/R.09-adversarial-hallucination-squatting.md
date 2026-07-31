---
sigil_guard:
  id: "R.09"
  topic: "Adversarial Hallucination Squatting Across The Agent Resource Path"
  category: research
  status: complete
  created: "2026-07-31"
  updated: "2026-07-31"
  decision: adopted
  tags:
    [
      "hallusquatting",
      "slopsquatting",
      "prompt-injection",
      "agent-skills",
      "supply-chain",
      "resource-provenance",
      "sandbox",
      "reference-path"
    ]
---

# R.09 - Adversarial Hallucination Squatting Across The Agent Resource Path

## Executive Summary

Adversarial hallucination squatting is a credible composition of resource-name
hallucination, public namespace registration, indirect prompt injection, and
excessive agent authority. The strongest current demonstration is a July 2026
preprint rather than a peer-reviewed or independently replicated result, but
its premises are supported independently by peer-reviewed package-hallucination
research, established indirect-prompt-injection literature, and recent
behavioral studies of malicious agent skills.

SigilGuard should adopt the attack as an end-to-end reference-path scenario,
not as a new detector, resolver, registry client, reputation service, or
sandbox. Resolution and artifact acquisition remain host-owned; process,
filesystem, credential, and network isolation remain execution-runtime
responsibilities. SigilGuard's natural seam begins when the host labels a
resource boundary: it can preserve untrusted influence, mediate later tool
requests, apply deterministic isolation policy, bind approval to an exact
action and sandbox, and record evidence. No new public API is justified until
an integration experiment shows that the existing boundary vocabulary cannot
express those facts without ambiguity.

## Research Question

Does adversarial hallucination squatting introduce a distinct and material
threat to the reference path, and, if so, which controls belong naturally in
SigilGuard rather than in the host resolver, package or source platform,
execution sandbox, or operating system?

The question has three subsidiary parts:

1. How strong is the evidence that model-generated resource identifiers are
   predictable and exploitable?
2. Which proposed mitigations break the demonstrated attack chain, and which
   merely reduce one observed symptom?
3. Can SigilGuard contribute a deterministic control at an existing trust
   boundary without absorbing resource discovery or execution responsibilities?

## Methodology

The review covered work available through July 31, 2026. Sources were ranked
by evidentiary weight:

1. peer-reviewed security research;
2. primary preprints with disclosed methods, sample sizes, and limitations;
3. maintained standards and official security guidance;
4. practitioner reports used only to discover candidate claims, then excluded
   from the evidentiary basis unless a primary paper or maintained standard
   corroborated them.

The review separated four claims that are often collapsed in secondary
discussion: models invent resource identifiers; invented identifiers recur;
an adversary can register them; and retrieved content can cause a privileged
effect. A mitigation was considered structural only if it interrupts at least
one transition without relying on the attacked model to classify its own input
correctly. Model refusal, keyword matching, search ranking, popularity, and
registry existence were treated as signals rather than proofs.

The July 2026 HalluSquatting study was read alongside the USENIX Security 2025
package-hallucination study, its 2026 frontier-model replication, research on
realistic library hallucinations, indirect prompt injection, capability-based
agent design, prompt-injection-resistant design patterns, retrieval poisoning,
and static skill-scanner evasion. SLSA, TUF, OWASP, and MCP guidance were used
to place controls at their proper system boundary.

The SigilGuard source, specifications, threat model, and reference consumer
contract were inspected read-only. No exploit payload was reproduced and no
public resource name was registered.

## Context

Agent resource acquisition crosses several independently owned trust domains:

```text
user intent
  -> model or planner
  -> resource resolver
  -> public namespace or registry
  -> fetcher and package tooling
  -> model context
  -> tool broker
  -> sandbox and operating system
```

SigilGuard occupies only part of this path. It is an embedded decision and
evidence library. It does not know the current contents of public registries,
does not establish which repository a natural-language label denotes, does not
fetch artifacts, and does not enforce kernel-level isolation. Treating the
library as though it owned the complete path would create a control that looks
comprehensive in isolation while leaving the real transitions unenforced.

The current architecture already carries the facts most relevant after
retrieval:

- `SigilGuard.Context` labels origin, resource URI, trust zone, sandbox
  identity, isolation level, and network posture.
- `SigilGuard.BoundaryPolicy` blocks tool requests in an untrusted trust zone
  and applies deterministic execute and network isolation rules.
- `SigilGuard.ToolGateway` and `SigilGuard.Runtime.Gate` bind guarded actions
  to payload and context evidence.
- `SigilGuard.Confirmation` binds approval to the exact action and sandbox.
- `SigilGuard.Hooks` lets the host add deny-side decisions without weakening
  the kernel.
- `SigilGuard.CapabilityManifest` pins MCP tool definitions and security
  properties; it is not an arbitrary package or repository manifest.

The applicability question is therefore not whether SigilGuard can recognize a
plausible-looking package name. It is whether the reference path preserves the
untrusted influence of retrieved material until every resulting side effect has
crossed a deterministic boundary.

## Threat Definition

Let `L` be a natural-language resource label supplied by a user, `I` an
identifier produced or selected by an agent, `R(I)` the public resource
registered at that identifier, `C` content retrieved from the resource, and
`A` a privileged action proposed after the model processes that content.

An adversarial hallucination-squatting chain requires all of the following:

1. **Ambiguous intent.** `L` does not uniquely establish a canonical resource
   identity, or the agent discards a canonical identifier the user supplied.
2. **Predictable substitution.** The resolver or model selects an unintended
   identifier `I` often enough for pre-registration to be useful.
3. **Attacker-controlled resolution.** A public platform permits the adversary
   to register or rank `R(I)` where the agent will retrieve it.
4. **Instruction ingestion.** Content `C` is processed in a context where data
   can influence instructions, plans, or tool selection.
5. **Authority propagation.** Action `A` receives shell, filesystem, secret, or
   network authority not independently justified by the user's original intent.
6. **Missing complete mediation.** The execution substrate does not enforce an
   independent policy at every side-effect boundary.

The chain fails if any necessary transition fails. This matters because no
single component needs to predict whether `I` was hallucinated. A host can make
the model's naming error irrelevant by requiring an intended canonical
identity before acquisition, or it can contain a mistaken acquisition by
preventing retrieved content from acquiring new authority.

## Findings

### HalluSquatting Demonstrates An Inference-Time Resource Attack

Spira et al. introduce adversarial hallucination squatting as an untargeted
promptware technique [1]. Their distinction from earlier package attacks is
substantive. Package slopsquatting compromises software generated downstream
from an LLM response; HalluSquatting compromises the agent application during
the same inference-time workflow in which it retrieves a repository or skill.

The paper studies recent repositories, older controls, and skills whose display
names diverge from their installable slugs. Across the reported experiments:

- recent repository names produced substantially more owner/slug
  hallucinations than older, well represented repositories;
- several models repeatedly produced self-referential `name/name` candidates;
- at least one registrable candidate appeared in the top ten universal scores
  for every trending repository evaluated;
- application behavior was decisive: search substantially improved repository
  resolution, but whether search occurred depended on the model and prompt;
- skill resolution remained exposed to direct slug generation, normalization,
  display-name divergence, and search-ranking manipulation;
- controlled end-to-end repository cases produced tool invocation or remote
  code execution in 20% to 65% of trials, depending on the application;
- controlled skill cases reached higher success rates in the three evaluated
  assistants after the squatted skill had been selected.

These results establish feasibility under the tested configurations. They do
not establish an active botnet or a population-wide compromise rate. The public
repository and skill registrations carried benign copies. Adversarial content
was introduced locally or privately for end-to-end evaluation, so public
platform malware detection was not exercised. The study is also a first
preprint whose product versions, model behavior, and marketplace ranking are
time-sensitive. Its strongest defensible conclusion is that the complete chain
is practical under controlled conditions, not that a HalluSquatting campaign
has been observed in the wild.

### Package Hallucinations Are Independently Established

Spracklen et al. provide the strongest peer-reviewed evidence for the naming
premise [2]. Their USENIX Security 2025 study generated 576,000 Python and
JavaScript code samples across 16 models. It measured package-hallucination
rates of at least 5.2% for commercial models and 21.7% for open models and found
205,474 unique hallucinated package names.

The study also tested retrieval augmentation, self-refinement, fine-tuning, and
an ensemble. Every method reduced hallucinations; none eliminated them. The
best reported ensemble still produced rates of 2.40% and 9.32% on the two
evaluated models. Fine-tuning reduced hallucination most strongly but degraded
HumanEval performance, sharply in one model.

Most importantly for security design, the authors reject a live master list of
currently valid package names as an effective defense. Once an adversary
publishes a hallucinated name, it enters that list. A curated set of expected
packages is stronger because it expresses authorization, while a registry
existence query expresses only availability.

Churilov's 2026 replication on five newer models reports a narrower overall
range of 4.62% to 6.10% [3]. It also identifies 127 names invented by all five
models, 53 of which remained registrable after coordinated disclosure. This
single-author preprint is weaker evidence than the USENIX study, but it
supports a careful conclusion: newer models appear to reduce variance and
headline rates without removing the shared, predictable tail that an attacker
would target.

Twist et al. study realistic developer-query variations across seven models
[4]. One-character misspellings, fabricated library premises, and time-related
questions materially changed hallucination behavior. The result matters beyond
packages: user phrasing and plausible false premises alter whether a model
challenges or normalizes an identifier. Krishna et al. likewise find that
language, model size, and task specificity affect package hallucination [5].
The error is conditional, not a stable model-wide percentage.

### The Payload Stage Is Indirect Prompt Injection

HalluSquatting supplies a scalable retrieval route, but the authority transfer
after retrieval is an indirect prompt-injection problem. Greshake et al.
established that attacker-controlled data likely to be retrieved by an
LLM-integrated application can manipulate API calls, exfiltrate data, and alter
application behavior without a direct attacker-to-user prompt channel [6].
The HalluSquatting chain changes how malicious content is selected; it does not
change the underlying confusion between data and instructions.

This distinction prevents a common design mistake. Eliminating identifier
hallucinations would remove one delivery route but would not make retrieved
repositories, package documentation, project rules, skills, webpages, or tool
results trustworthy. Conversely, a system that contains indirect prompt
injection through complete mediation remains protected even when it retrieves
the wrong resource.

CaMeL offers the strongest architectural evidence for this direction [7]. It
extracts control and data flow from trusted user intent and enforces
capabilities when tools are called, so untrusted data cannot silently change
program flow. It completed 77% of AgentDojo tasks with its stated security
guarantee, compared with 84% for an undefended system. The result demonstrates
a measurable utility cost but also shows why authorization outside the model
is qualitatively different from asking the model to recognize an injection.

Beurer-Kellner et al. generalize the same principle through prompt-injection-
resistant agent design patterns [8]. Their patterns differ operationally, but
all constrain how untrusted content can affect privileged control flow. This is
the relevant theoretical grounding for SigilGuard's source-to-sink policy
kernel.

### Static Skill Inspection Is Not A Load-Bearing Control

Ji et al. test eight agent-skill scanners against 1,613 malicious skills [9].
Their self-extracting packing technique bypasses every scanner at greater than
90%; structural transformations bypass most static scanners at greater than
80% and reach 96% against one hybrid scanner. These are payload-preserving
evasion results: the malicious behavior remains while its visible
representation changes.

Their behavior-oriented SkillDetonate system observes OS-boundary effects and
information flow in a sandbox. It detects 97% of controlled attacks at a 2%
false-positive rate and 87% of real-world malicious skills. This is strong
evidence for runtime observation and isolation, but it is not a proof of
safety. Path coverage and whether the agent actually triggers a payload still
limit detection.

The implication for SigilGuard is narrow. Built-in scanner and quarantine
signals remain useful for risk raising, operator explanation, and known-pattern
handling. They must not authorize installation or execution, and a clean scan
must never promote attacker-controlled resource content into a trusted zone.

### Search Before Fetch Reduces Error But Does Not Establish Identity

The HalluSquatting paper reports 93.4% correct repository resolution when
Cursor searched and only 0.9% when it did not [1]. Enforcing search before
fetch is therefore a worthwhile application control. It is not a complete
security control for four reasons:

1. the searched condition still produced 6.6% incorrect identifiers;
2. skill-search ranking could be displaced by attacker-controlled names and
   English metadata;
3. a newly registered hallucinated identifier becomes a valid search result;
4. a search result does not state which publisher, namespace, or artifact the
   user intended.

Retrieval systems are themselves adversarial surfaces. Zou et al. demonstrate
that an attacker can poison retrieval-augmented generation knowledge bases to
control answers with a small number of malicious documents [10]. The setting
differs from public repository search, but it supports the general rule that
retrieval output is evidence to verify, not an authorization oracle.

A sound resolver distinguishes an exact identifier from an ambiguous label.
When the user supplies a fully qualified source, the model must not rewrite it.
When the user supplies a display name, the host must resolve it to a canonical
registry, namespace, publisher, and immutable revision before activation.
Ambiguity is a product state to surface, not a gap for the model to fill.

### Provenance Proves Origin Only Against An Expectation

Artifact digests, signatures, SLSA provenance, and TUF metadata protect
different transitions. None can infer user intent from an ambiguous label.

SLSA verification binds an artifact to signed provenance and a configured root
of trust, then compares builder identity, canonical source repository, build
type, and external parameters against expectations [11]. The specification
explicitly notes that its current build model does not cover tricking a
consumer into selecting an unintended package, such as typosquatting.
A malicious publisher can sign a malicious artifact correctly; verification
becomes an authorization control only when the verifier already knows which
publisher, source, and build process are expected.

TUF protects clients against arbitrary target substitution, rollback, freeze,
and mix-and-match attacks through signed role metadata, versions, expiry, and
target hashes [12]. Its wrong-software property assumes that the application
has identified the target the client wanted. It secures distribution after
selection; it does not resolve a model-generated natural-language reference.

The reference path therefore needs two distinct bindings:

- **identity binding:** this canonical namespace and publisher are the intended
  source for the requested capability;
- **artifact binding:** these immutable bytes are the version that was
  selected and authorized.

Popularity, download count, age, search rank, transport security, signatures,
and static scans may contribute risk signals. None substitutes for both
bindings.

### Excessive Authority Determines Impact

The attack's final impact depends less on the name error than on the authority
available after retrieval. OWASP characterizes damaging agent behavior as the
combination of excessive functionality, permissions, or autonomy and
recommends granular tools, least privilege, human approval for high-impact
operations, and complete mediation in downstream systems [13].

The MCP security guidance reaches the same operational conclusion for locally
executed servers: show exact commands, require consent, run with minimal
privileges, and restrict filesystem and network access [14]. Current MCP client
guidance further requires host mediation for calls originating in a sandbox,
keeps credentials in the host, and recommends no direct sandbox network access
[15].

These controls address the complete class rather than one name-generation
mechanism. An artifact fetched under the wrong identity can be inspected
safely when it has no credentials, host filesystem, direct network, or
unmediated process authority. A correctly named but compromised artifact
requires the same containment.

## Attack-Class Boundaries

| Class | Error or adversary input | Compromised subject | Distinguishing control |
|-------|--------------------------|---------------------|------------------------|
| Typosquatting | Human mistypes or misreads an identifier. | Human or installer selects attacker resource. | Canonical identity, confusable-name policy, review. |
| Dependency confusion | Resolver precedence selects an unintended public or private package. | Build or install process. | Namespace ownership and resolver precedence policy. |
| Package slopsquatting | Model emits a nonexistent dependency later registered by an attacker. | Generated software or its build. | Curated dependency expectations, immutable lock and artifact verification. |
| HalluSquatting | Agent invents or normalizes a repository or skill identifier during retrieval. | Agent application at inference time. | Canonical resolution plus containment of retrieved influence. |
| Ordinary malicious resource | User or agent selects an attacker resource without hallucinating. | Agent, build, or runtime. | The same provenance, mediation, and isolation controls. |

The last row is important: HalluSquatting is a novel selection mechanism, not a
novel reason to trust retrieved content. Controls should remain effective when
the resource is malicious for any reason.

## Control Ownership Across The Reference Path

| Transition | Required invariant | Natural owner | SigilGuard role |
|------------|--------------------|---------------|-----------------|
| User label to candidate | Exact identifiers are preserved; ambiguous labels remain unresolved until authoritative lookup. | Host planner and resolver. | None. |
| Candidate to selected identity | Registry, namespace, publisher, and canonical source match an established or explicitly approved expectation. | Host policy and ecosystem adapter. | May record a host decision; must not perform discovery. |
| Selected identity to bytes | Revision is immutable; received digest and provenance match the selection; redirects cannot substitute another origin. | Fetcher, package manager, source platform. | Can bind supplied digest evidence; must not fetch. |
| Bytes to model context | Retrieved instructions remain external, resource-origin, and untrusted. | Host orchestration. | Context, gate, scanner signals, and audit. |
| Resource-influenced plan to tool request | Untrusted influence cannot silently gain shell, network, secret, or write authority. | Host tool broker plus SigilGuard. | Deterministic boundary verdict and exact-action binding. |
| Tool request to effect | Filesystem, process, credentials, and network are restricted independently of model intent. | Sandbox, OS, container, downstream service. | Require and attest isolation facts; does not implement isolation. |
| Effect to evidence | Decisions are reconstructable without leaking protected content. | Host audit integration plus SigilGuard. | Sanitized decision evidence and tamper-evident audit. |

## Comparative Analysis

| Criterion | Keyword or model detector | Mandatory search before fetch | Signature or provenance only | Structural reference-path mediation |
|-----------|---------------------------|-------------------------------|------------------------------|-------------------------------------|
| Stops invented names | Sometimes | Often, not always | No | Yes when canonical expectation is required |
| Stops a registered squat | Unreliable | No; it is now a search result | Only if signer/source expectation differs | Yes |
| Stops malicious legitimate resources | Unreliable | No | Only substitution, not authorized malice | Contains effects |
| Robust to obfuscation | No | Not applicable | Yes for byte identity, not behavior | Yes when authority is enforced outside content |
| Depends on model cooperation | Usually | Planner may, fetch tool need not | No | No |
| Handles mutable artifacts | No | No | Yes when revision and digest are checked | Yes |
| Natural SigilGuard fit | Advisory signal only | No; host network behavior | Evidence input only | Yes at the boundary-policy slice |
| Residual risk | High and adaptive | Wrong/ranked/registered results | Correctly signed malicious publisher | Sandbox escape, policy error, missing provenance propagation |
| Decision | reject as primary control | adopt as defense in depth | adopt with expectations | adopt as primary architecture |

## Falsifiable Reference-Path Validation

Before any SigilGuard API change, the reference path should be evaluated with a
benign end-to-end scenario:

1. A recent resource is requested by display name without a namespace.
2. A controlled resolver returns a plausible self-referential squat.
3. The resource carries a harmless marker instruction that proposes a simulated
   shell or network action.
4. The test records identity selection, fetched digest, model-ingress labels,
   the derived tool request, sandbox facts, and the final decision.

The experiment should vary the following conditions:

- exact canonical identifier versus ambiguous display name;
- search absent, search present, and attacker-ranked search result;
- resource absent before registration and present afterward;
- immutable revision versus a moved tag;
- expected versus unexpected publisher;
- clean text versus packed or structurally obfuscated auxiliary content;
- direct action versus an action caused by a project-rule or skill file;
- fresh approval versus a different resource, digest, action, or sandbox;
- verification available, stale, malformed, or unavailable.

The architecture can claim mitigation only when all of these properties hold:

- an ambiguous label cannot activate an artifact without canonical identity
  selection;
- approval cannot survive a namespace, revision, digest, argument, or sandbox
  change;
- retrieved resource content cannot grant itself additional authority;
- shell, filesystem, credential, and network effects are mediated even when
  content scanning produces no finding;
- failed verification closes the activation path;
- evidence contains no raw credential or protected payload;
- legitimate exact-identifier and read-only inspection workflows remain usable
  and their confirmation rate is measured.

If the existing host and SigilGuard contracts satisfy these properties, the
correct result is documentation and scenario evidence, not a new module. If
the test fails because the host drops resource influence before a later tool
request, the first fix belongs in orchestration. Only if an existing generic
boundary cannot carry the necessary fact should SigilGuard consider an
additive, attack-agnostic contract.

## Recommendation

**Decision:** adopted.

Adopt adversarial hallucination squatting as a reference-path threat scenario
and extend the control mapping only at boundaries the project actually owns.
The primary control is structural mediation:

1. the host preserves exact identifiers and resolves ambiguous labels;
2. selection binds canonical identity to an established or explicit
   expectation;
3. acquisition binds immutable bytes to that selection;
4. retrieved content remains resource-origin and untrusted;
5. every derived side effect crosses the tool broker and deterministic policy;
6. execution occurs with independently enforced least privilege and isolation.

Use mandatory search, static scanning, model-based classification, popularity,
age, and registry reputation only as defense-in-depth signals. Do not claim
that they prevent the attack.

Reject a `HalluSquatting`-named detector, a package-name heuristic, a public
registry client, or artifact reputation in SigilGuard core. Reject extending
`CapabilityManifest` into a generic repository or package manifest: its
existing subject is a reviewed MCP tool definition, and overloading it would
blur two trust domains. Do not place security-critical resolver facts solely in
unbounded `Context.metadata`, which is intentionally excluded from canonical
decision evidence.

Defer any new public SigilGuard field or statement type until the falsifiable
reference-path experiment identifies a generic evidence gap. A future addition
must bind a host-verified fact, remain transport- and ecosystem-neutral, and
improve controls for ordinary malicious resources as well as hallucinated
ones.

## Impact On SigilGuard

- Modules affected now: none; the existing natural seam is
  `SigilGuard.Context`, `SigilGuard.BoundaryPolicy`,
  `SigilGuard.Runtime.Gate`, `SigilGuard.ToolGateway`,
  `SigilGuard.Confirmation`, `SigilGuard.Hooks`, and audit evidence.
- Specs to create/update: no new spec yet. A later documentation/spec pass
  should update the R.06 control mapping and SP.04/SP.07/SP.14 scenario
  guidance only after the reference-path validation establishes the exact
  integration facts. SP.15 should own any comparative benchmark methodology.
- Tasks affected: a future task may add the isolated reference-path scenario
  and its evidence assertions; no implementation task is justified by this
  research note alone.
- Migration needed: none.
- Breaking changes: none.
- Network or registry impact: none; discovery and fetch remain host-owned.
- Reference-consumer impact: validate provenance propagation and complete
  mediation before proposing a library change.

## Limitations

- The HalluSquatting paper is a first preprint and has not yet been
  independently replicated.
- Its malicious end-to-end payloads were evaluated locally or privately, so
  public platform detection and takedown were not part of the measured chain.
- Model, application, marketplace, and search behavior are version-sensitive.
- Published experiments emphasize recent and ambiguous resources; they do not
  measure how often the reference consumer receives such requests.
- Package-hallucination rates do not directly predict repository or skill
  attack rates.
- Behavior-oriented sandbox auditing substantially improves detection but
  remains incomplete and does not replace preventive isolation.
- There is no primary evidence reviewed here of an operational
  HalluSquatting-derived botnet. The research demonstrates feasibility and
  scalable targeting conditions.

These limitations lower confidence in prevalence estimates, not in the need
for canonical identity, untrusted-content labeling, complete mediation, and
least privilege. Those controls also protect against non-hallucinated
malicious resources.

## Sources

### Research Papers

1. Aya Spira, Stav Cohen, Elad Feldman, Ron Bitton,
   Avishai Wool, and Ben Nassi, [“Beware of Agentic Botnets: Scalable
   Untargeted Promptware Attacks via Universal and Transferable Adversarial
   HalluSquatting”](https://arxiv.org/abs/2607.07433), arXiv:2607.07433,
   2026.
2. Joseph Spracklen, Raveen Wijewickrama, A H M Nazmus
   Sakib, Anindya Maiti, and Bimal Viswanath,
   [“We Have a Package for You! A Comprehensive Analysis of Package
   Hallucinations by Code Generating LLMs”](https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen),
   34th USENIX Security Symposium, 2025. Distinguished Paper Award.
3. Aleksandr Churilov,
   [“The Range Shrinks, the Threat Remains: Re-evaluating LLM Package
   Hallucinations on the 2026 Frontier-Model Cohort”](https://arxiv.org/abs/2605.17062),
   arXiv:2605.17062v2, 2026.
4. Lukas Twist, Jie M. Zhang, Mark Harman, and Helen
   Yannakoudakis,
   [“Library Hallucinations in LLM-Generated Code: A Risk Analysis Grounded
   in Developer Queries”](https://arxiv.org/abs/2509.22202),
   arXiv:2509.22202v3, 2026.
5. Arjun Krishna, Erick Galinkin, Leon Derczynski, and
   Jeffrey Martin,
   [“Importing Phantoms: Measuring LLM Package Hallucination
   Vulnerabilities”](https://arxiv.org/abs/2501.19012), arXiv:2501.19012,
   2025.
6. Kai Greshake, Sahar Abdelnabi, Shailesh Mishra,
   Christoph Endres, Thorsten Holz, and Mario Fritz,
   [“Not What You've Signed Up For: Compromising Real-World LLM-Integrated
   Applications with Indirect Prompt Injection”](https://arxiv.org/abs/2302.12173),
   arXiv:2302.12173, 2023.
7. Edoardo Debenedetti et al.,
   [“Defeating Prompt Injections by Design”](https://arxiv.org/abs/2503.18813),
   arXiv:2503.18813v2, 2025.
8. Luca Beurer-Kellner et al.,
   [“Design Patterns for Securing LLM Agents against Prompt
   Injections”](https://arxiv.org/abs/2506.08837), arXiv:2506.08837v3,
   2025.
9. Zimo Ji, Congying Xu, Zongjie Li, Yudong Gao, Xin Wei,
   Shuai Wang, and Shing-Chi Cheung,
   [“Cloak and Detonate: Scanner Evasion and Dynamic Detection of Agent Skill
   Malware”](https://arxiv.org/abs/2607.02357), arXiv:2607.02357, 2026.
10. Wei Zou et al.,
    [“PoisonedRAG: Knowledge Corruption Attacks to Retrieval-Augmented
    Generation of Large Language Models”](https://www.usenix.org/conference/usenixsecurity25/presentation/zou-poisonedrag),
    34th USENIX Security Symposium, 2025.

### Standards And Maintained Guidance

11. [SLSA v1.2 - Verifying Artifacts](https://slsa.dev/spec/v1.2/verifying-artifacts).
12. [The Update Framework Specification](https://theupdateframework.github.io/specification/latest/).
13. [OWASP LLM06:2025 - Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/).
14. [Model Context Protocol - Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices).
15. [Model Context Protocol - Client Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/develop/clients/client-best-practices).
