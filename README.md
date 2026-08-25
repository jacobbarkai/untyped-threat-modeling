# untyped-threat-modeling

[![DOI](https://zenodo.org/badge/1346408316.svg)](https://doi.org/10.5281/zenodo.22100345)
[![License: CC0-1.0](https://img.shields.io/badge/License-CC0_1.0-lightgrey.svg)](LICENSE)

Threat modeling from an untyped property graph. No component taxonomy, no rule set, no schema.

Automated threat modeling usually parses an artifact, maps what it finds onto a library of known component types, assembles a data flow diagram, and runs rules keyed to those types. The mapping step looks like a parsing convenience. It is the index the whole rule set is keyed against, and it imposes a bound: **a component the taxonomy cannot name is a component the rules cannot reach.**

This is a working demonstration of the same job done without that step. A node is an integer and an unordered bag of raw strings, exactly as they appeared in the source. An edge is a pair of integers. Interpretation is done by a model reading the strings, not by code matching them.

## Try it in thirty seconds, with no API key

Extraction from HCL is deterministic, so this needs no provider, no key and no SDK:

```bash
git clone https://github.com/jacobbarkai/untyped-threat-modeling
cd untyped-threat-modeling
python untyped_threat_model.py --iac sample.tf --extract-only
```

Look at vertex 5 in the output:

```
5  medical_device_ble_pairing.bedside_monitor
   ['block=resource', 'type=medical_device_ble_pairing', 'label=bedside_monitor',
    'pairing_mode=just_works', 'firmware=2.1.0',
    'uplink=aws_api_gateway_rest_api.public.id']
```

That resource type does not exist in AWS. No provider defines it. A taxonomy driven parser has nothing to map it to and will either discard it or call it a generic process. Here it reaches analysis with `pairing_mode=just_works` intact, and anything that has read the Bluetooth specifications knows that Just Works pairing offers no man in the middle protection.

That difference is the point of the whole repository. A taxonomy driven method **degrades to silence** at the edge of its knowledge. This one **degrades to inference from whatever the strings assert**, which is what a human reviewer does.

## Full usage

```bash
pip install anthropic        # or: pip install openai
cp env.example .env          # then edit one block

python untyped_threat_model.py --iac main.tf --svg out.svg
python untyped_threat_model.py --code app.py
python untyped_threat_model.py --image whiteboard.jpg
python untyped_threat_model.py --iac main.tf --audit
```

| Flag | Effect |
|---|---|
| `--iac FILE` | Terraform or other HCL. Extraction is deterministic |
| `--code FILE` | A source file in any language. Extraction uses a model |
| `--image FILE` | An architecture diagram or a photograph of a whiteboard |
| `--extract-only` | Stop after the topology. With `--iac`, needs no provider |
| `--audit` | Enumerate every vertex against every STRIDE category, negatives included |
| `--svg FILE` | Force directed rendering |
| `--json FILE` | Write the raw topology |

## Providers

`LLM_PROVIDER=anthropic` uses that SDK and keeps adaptive thinking. Anything else speaks the OpenAI `/v1/chat/completions` protocol, so a base URL, a key and a model name reach OpenAI, DeepSeek, xAI, Mistral, Groq, OpenRouter, and a local Ollama or vLLM. See [`env.example`](env.example).

Structured output is requested as `json_schema`, falls back to `json_object`, then to a prompt instruction, so a provider supporting none of the three still works with weaker guarantees.

## The audit mode, and why enumeration is possible here

The usual objection to replacing a rule engine is that a rule engine can enumerate what it considered and a model cannot. That is true of the enumeration a rule engine performs, which runs over **component types** crossed with threat patterns. The component type axis is open ended and proprietary.

The threat category axis is not. STRIDE has six categories, LINDDUN seven, both published and stable, and both **independent of component type**: whether something is subject to spoofing is answerable without knowing what it is. So `--audit` decides every cell of vertices against categories, reports negatives with their reasoning, and checks the returned cell count against the expected one so a short return is flagged rather than passed off as clean.

The component taxonomy stays deleted. Threat categories are enumerated; component types are not.

## What this does not do

Four objections apply, and none of them has gone away:

- **Auditability.** A model cannot be proven to have reasoned *well* within a cell. Completeness is demonstrable, quality is not. Same standard as a human led threat model.
- **Reproducibility.** Bit for bit regeneration is unavailable, and a pinned model identifier can be retired by its provider. Archive outputs rather than assuming you can regenerate them.
- **Recall.** Differential comparison, self consistency, seeded corpora and cross model agreement all estimate recall relative to something. None yields absolute recall.
- **Scale.** Edge lists consume context. Real estates need subgraph extraction by reachability from ingress vertices, which is not implemented here.

## The suggested use

Do not replace a rule engine with this. Run both over the same artifact and diff the results.

Threats found by the untyped pass on which no rule fired are candidate gaps in the rule set. Threats the rules found and this missed calibrate how far it can be trusted. Components it declares uninterpretable identify what a taxonomy is coercing to a generic type in silence.

Across a few dozen architectures that diff characterises where a taxonomy is blind, which is information a taxonomy cannot produce about itself.

**If you run it against real infrastructure, please open an issue with what the diff looked like, particularly if the answer was nothing.** Negative results are the useful ones here.

## What the output looks like

[**sample-output.md**](sample-output.md) has real runs of all three modes against `sample.tf`, reproduced verbatim, so the behaviour can be judged without spending tokens.

## The article

The full argument, with diagrams, the four objections worked through, and the prior work discussed properly: [**ARTICLE.md**](ARTICLE.md).

## Prior work

The field has moved in the opposite direction for a decade, toward more formal type systems, and for defensible reasons.

- Bromander, Jøsang, Eian, [Semantic Cyberthreat Modelling](https://stids.c4i.gmu.edu/papers/STIDSPapers/STIDS2016_A2_BromanderJosangEian.pdf), STIDS 2016
- OWASP [Ontology-Driven Threat Modeling Framework](https://owasp.org/www-project-ontology-driven-threat-modeling-framework/)
- [A Semantic Threat Model to Evaluate Security Threats in Cyber-Physical Systems](https://doi.org/10.1145/3777450), ACM TCPS, January 2026
- [ASTRAL](https://arxiv.org/abs/2604.05674), multimodal LLMs reconstructing architecture from fragmented documentation
- [SMSI](https://arxiv.org/abs/2604.23905), neuro-symbolic inference from SysML with CPE identifiers

No component of the architecture here is new either. Force directed layout is [Fruchterman and Reingold, 1991](https://doi.org/10.1002/spe.4380211102). Schema free property graphs are [Neo4j](https://neo4j.com/docs/getting-started/appendix/graphdb-concepts/) and [RDF](https://www.w3.org/RDF/). Styling decoupled from structure is what [Graphviz DOT attributes](https://graphviz.org/doc/info/attrs.html) have done since the nineties. What changed is that interpreting the strings no longer has to be done by code.

## Licence

CC0 1.0 Universal. Public domain. Take it, change it, ship it in a product, attribute nothing.
