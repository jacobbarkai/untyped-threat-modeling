#!/usr/bin/env python3
"""
untyped_threat_model.py

A working demonstration of threat modeling without an object library.

The usual pipeline is: parse -> map onto a closed set of typed objects -> assemble a
DFD -> run rules keyed to the object types. This script deletes the second step.

Nothing here knows what an S3 bucket is. There is no type enum, no component
catalogue, no rule set, and no schema. A node is an integer and an unordered bag of
raw strings exactly as they appeared in the source. An edge is a pair of integers.
Interpretation is done by a model reading those strings, not by code matching them.

The interesting property is what happens at the edge of knowledge. A library based
tool meeting an unfamiliar component degrades to silence, because an entity it cannot
name is an entity it cannot analyse. This degrades to reasoning from whatever the
strings say, which is what a human reviewer does.

Provider is configured through the environment or a .env file, see env.example.
LLM_PROVIDER=anthropic uses the native SDK and keeps adaptive thinking; anything else
uses the OpenAI /v1/chat/completions protocol, which most other vendors speak, so
LLM_BASE_URL plus LLM_API_KEY plus LLM_MODEL reaches DeepSeek, xAI, Mistral, Groq,
OpenRouter, Ollama, vLLM and the rest.

Usage:
    cp env.example .env     # then edit one block
    pip install anthropic   # or: pip install openai

    # Deterministic, needs no provider, no key and no SDK:
    python untyped_threat_model.py --iac main.tf --extract-only

    python untyped_threat_model.py --iac main.tf
    python untyped_threat_model.py --code app.py
    python untyped_threat_model.py --image architecture.png
    python untyped_threat_model.py --iac main.tf --svg out.svg --json topology.json

    # Audit mode: decide every vertex against every STRIDE category and report the
    # negatives too, so the record shows what was considered rather than only what
    # was found. See the comment above STRIDE for why this is enumerable at all.
    python untyped_threat_model.py --iac main.tf --audit

Licence: public domain. Take it, change it, ship it.
"""

import argparse
import base64
import json
import math
import os
import random
import re
import sys
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Provider configuration.
# ---------------------------------------------------------------------------
#
# Most vendors now speak the OpenAI /v1/chat/completions protocol, so base URL plus
# key plus model name covers OpenAI, DeepSeek, Groq, Together, Fireworks, xAI,
# Mistral, OpenRouter, Ollama and vLLM. That is the default path here.
#
# Three things are NOT interchangeable across providers, which is why this is an
# adapter rather than a base_url swap:
#
#   1. Structured output. Anthropic uses output_config.format; the OpenAI protocol
#      uses response_format, and support ranges from full json_schema through
#      json_object to nothing at all. Handled by degrading in that order.
#   2. Image blocks. Anthropic takes {"type": "image", "source": {...}}; the OpenAI
#      protocol takes {"type": "image_url", "image_url": {"url": "data:..."}}.
#   3. Adaptive thinking and effort are Anthropic-only, and this task benefits from
#      them, so the native path is kept rather than flattened away.

def load_dotenv(path=".env") -> None:
    """Minimal .env reader: KEY=value, # comments, optional quotes, no interpolation.

    Deliberately not python-dotenv. One less dependency for a script whose whole
    point is that it is small enough to read.
    """
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip().strip('"').strip("'")
            os.environ.setdefault(key, val)


class LLM:
    """One method, `json()`, over whichever provider the environment names.

    LLM_PROVIDER   openai (default) | anthropic
    LLM_BASE_URL   e.g. https://api.deepseek.com/v1 . Ignored for anthropic.
    LLM_API_KEY    falls back to OPENAI_API_KEY / ANTHROPIC_API_KEY
    LLM_MODEL      e.g. gpt-4o, deepseek-chat, claude-opus-5
    """

    def __init__(self) -> None:
        load_dotenv()
        self.provider = os.environ.get("LLM_PROVIDER", "openai").strip().lower()
        self.model = os.environ.get("LLM_MODEL") or (
            "claude-opus-5" if self.provider == "anthropic" else "gpt-4o")
        self.key = (os.environ.get("LLM_API_KEY")
                    or os.environ.get("ANTHROPIC_API_KEY" if self.provider == "anthropic"
                                      else "OPENAI_API_KEY"))
        self.base_url = os.environ.get("LLM_BASE_URL")

        if self.provider == "anthropic":
            try:
                import anthropic
            except ImportError:
                sys.exit("pip install anthropic   (or set LLM_PROVIDER=openai)")
            self._client = anthropic.Anthropic(api_key=self.key) if self.key \
                else anthropic.Anthropic()
        else:
            try:
                from openai import OpenAI
            except ImportError:
                sys.exit("pip install openai   (or set LLM_PROVIDER=anthropic)")
            if not self.key:
                sys.exit("set LLM_API_KEY (or OPENAI_API_KEY) in the environment or .env")
            self._client = OpenAI(api_key=self.key, base_url=self.base_url)

    def describe(self) -> str:
        where = self.base_url or ("api.anthropic.com" if self.provider == "anthropic"
                                  else "api.openai.com")
        return f"{self.provider}:{self.model} via {where}"

    @staticmethod
    def image_block(media: str, b64: str, provider: str) -> dict:
        if provider == "anthropic":
            return {"type": "image",
                    "source": {"type": "base64", "media_type": media, "data": b64}}
        return {"type": "image_url",
                "image_url": {"url": f"data:{media};base64,{b64}"}}

    def json(self, system: str, blocks: list, schema: dict, max_tokens: int = 16000) -> dict:
        """Return a dict conforming to `schema`, whatever the provider supports."""
        if self.provider == "anthropic":
            resp = self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                thinking={"type": "adaptive"},
                system=system,
                messages=[{"role": "user", "content": blocks}],
                output_config={"effort": "high",
                               "format": {"type": "json_schema", "schema": schema}},
            )
            return json.loads(next(b.text for b in resp.content if b.type == "text"))

        messages = [{"role": "system", "content": system},
                    {"role": "user", "content": blocks}]

        # Degrade rather than fail: strict schema, then any JSON object, then plain
        # text with the schema described in the prompt. A provider that supports none
        # of the three still works, just with weaker guarantees.
        attempts = [
            {"response_format": {"type": "json_schema", "json_schema":
                                 {"name": "result", "schema": schema, "strict": True}}},
            {"response_format": {"type": "json_object"}},
            {},
        ]
        last = None
        for extra in attempts:
            try:
                resp = self._client.chat.completions.create(
                    model=self.model, max_tokens=max_tokens,
                    messages=messages, **extra)
                return _parse_json(resp.choices[0].message.content)
            except Exception as err:  # noqa: BLE001 - provider errors are not a fixed type
                last = err
                if not extra:  # the bare attempt failed too; nothing left to try
                    break
                messages[0] = {"role": "system", "content":
                               system + "\n\nRespond with JSON only, matching this schema:\n"
                               + json.dumps(schema)}
        sys.exit(f"model call failed ({self.describe()}): {last}")


def _parse_json(text: str) -> dict:
    """Tolerate markdown fences and leading prose, which smaller models emit."""
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            raise
        return json.loads(text[start:end + 1])


# ---------------------------------------------------------------------------
# The only data structure in this program.
# ---------------------------------------------------------------------------

@dataclass
class Topology:
    """An untyped directed graph.

    `attributes` maps a vertex to raw strings from the source. Not parsed into
    fields, not normalised, not validated against anything. `aws_s3_bucket`,
    `acl=public-read` and `versioning=false` are peers: three strings in a bag.

    Nothing is thrown away, because nothing was ever selected for keeping.
    """
    attributes: dict[int, list[str]] = field(default_factory=dict)
    edges: list[tuple[int, int]] = field(default_factory=list)
    labels: dict[int, str] = field(default_factory=dict)  # display only

    def add(self, label: str, strings: list[str]) -> int:
        vid = len(self.attributes)
        self.attributes[vid] = strings
        self.labels[vid] = label
        return vid

    def payload(self) -> dict:
        """What gets sent for analysis. No diagram, no types, no schema."""
        return {
            "vertices": sorted(self.attributes),
            "attributes": {str(k): v for k, v in sorted(self.attributes.items())},
            "edges": [list(e) for e in self.edges],
        }


# ---------------------------------------------------------------------------
# Extraction. Deterministic for IaC, model assisted for code and images.
# ---------------------------------------------------------------------------

# Matches `resource "aws_s3_bucket" "exports" {`, `module "vpc" {`, `provider "aws" {`.
# Note it captures the type as a *string to carry forward*, never as a type to switch on.
_BLOCK = re.compile(r'^\s*([a-z_]+)\s+"([^"]+)"(?:\s+"([^"]+)")?\s*\{', re.M)
_ASSIGN = re.compile(r'^\s*([A-Za-z_][\w.-]*)\s*=\s*(.+?)\s*$', re.M)


def _block_body(text: str, open_brace: int) -> str:
    """Return the text between a `{` and its matching `}`."""
    depth, i = 0, open_brace
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace + 1:i]
        i += 1
    return text[open_brace + 1:]


def from_iac(source: str) -> Topology:
    """Parse HCL into a graph. No mapping table is consulted, because there isn't one.

    This is the step that usually reaches for an object library. Here the resource
    type survives as the literal string `type=aws_s3_bucket`, which the model can
    reason about, rather than being cast to a `Bucket` object whose fields somebody
    chose in advance. When Terraform ships a resource nobody has seen before, this
    keeps working.
    """
    topo = Topology()
    by_address: dict[str, int] = {}

    for m in _BLOCK.finditer(source):
        kind, first, second = m.group(1), m.group(2), m.group(3)
        body = _block_body(source, m.end() - 1)

        # `label=` not `name=`: the block's own second quoted string, kept distinct from
        # any `name = "..."` assignment inside the body. Both survive; neither wins.
        strings = [f"block={kind}", f"type={first}"]
        if second:
            strings.append(f"label={second}")
        for a in _ASSIGN.finditer(body):
            key, val = a.group(1), a.group(2).rstrip(",").strip()
            val = val.strip('"')
            if val and not val.startswith("{"):
                strings.append(f"{key}={val}")

        label = f"{first}.{second}" if second else first
        vid = topo.add(label, strings)
        if second:
            by_address[f"{first}.{second}"] = vid

    # Edges are references between blocks. Also purely textual: if one block's body
    # mentions another block's address, that is an edge. No knowledge of what
    # "depends on" means for any particular resource type.
    for m in _BLOCK.finditer(source):
        kind, first, second = m.group(1), m.group(2), m.group(3)
        if not second:
            continue
        src = by_address.get(f"{first}.{second}")
        body = _block_body(source, m.end() - 1)
        for address, dst in by_address.items():
            if dst != src and re.search(rf"\b{re.escape(address)}\b", body):
                topo.edges.append((dst, src))

    return topo


_EXTRACT_SCHEMA = {
    "type": "object",
    "properties": {
        "nodes": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "label": {"type": "string"},
                    "strings": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["label", "strings"],
                "additionalProperties": False,
            },
        },
        "edges": {
            "type": "array",
            "items": {"type": "array", "items": {"type": "integer"}},
        },
    },
    "required": ["nodes", "edges"],
    "additionalProperties": False,
}

_EXTRACT_SYSTEM = """You extract a directed graph from an artifact.

Emit nodes and edges only. For each node give a short display label and a bag of raw
strings taken from the artifact as literally as possible: identifiers, configuration
keys and values, protocol names, ports, annotations, comments, anything written down.

Do NOT classify nodes into types like process, data store or external entity. Do NOT
normalise vocabulary. Do NOT invent attributes that are not present. If the artifact
says `just_works`, the string is `just_works`.

Edges are [source_index, target_index] into your own nodes array, direction of data
flow or invocation where the artifact makes that visible."""


def from_model(llm: LLM, blocks: list, what: str) -> Topology:
    """Extraction for inputs a regex cannot handle: images, and code in any language."""
    data = llm.json(
        _EXTRACT_SYSTEM,
        blocks + [{"type": "text", "text": f"Extract the graph from this {what}."}],
        _EXTRACT_SCHEMA,
    )

    topo = Topology()
    for n in data.get("nodes", []):
        topo.add(n["label"], n["strings"])
    for e in data.get("edges", []):
        if len(e) == 2 and all(v in topo.attributes for v in e):
            topo.edges.append((e[0], e[1]))
    return topo


def from_image(llm: LLM, path: str) -> Topology:
    ext = os.path.splitext(path)[1].lower()
    media = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
             ".gif": "image/gif", ".webp": "image/webp"}.get(ext, "image/png")
    with open(path, "rb") as f:
        data = base64.standard_b64encode(f.read()).decode()
    return from_model(llm, [LLM.image_block(media, data, llm.provider)],
                      "architecture diagram")


def from_code(llm: LLM, source: str) -> Topology:
    return from_model(llm, [{"type": "text", "text": source}], "code snippet")


# ---------------------------------------------------------------------------
# Analysis. The graph goes in. No diagram is drawn, no rule fires.
# ---------------------------------------------------------------------------

_ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "boundaries": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "label": {"type": "string"},
                    "members": {"type": "array", "items": {"type": "integer"}},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["label", "members", "evidence"],
                "additionalProperties": False,
            },
        },
        "threats": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string",
                                 "enum": ["critical", "high", "medium", "low"]},
                    "path": {"type": "array", "items": {"type": "integer"}},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                    "reasoning": {"type": "string"},
                },
                "required": ["title", "severity", "path", "evidence", "reasoning"],
                "additionalProperties": False,
            },
        },
        "uninterpreted": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "vertex": {"type": "integer"},
                    "why": {"type": "string"},
                },
                "required": ["vertex", "why"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["boundaries", "threats", "uninterpreted"],
    "additionalProperties": False,
}

_ANALYSIS_SYSTEM = """You are given a directed graph. Vertices are integers. Each vertex
has a bag of raw strings taken verbatim from an infrastructure artifact. There are no
types and no schema. Some strings will be unfamiliar; reason from them anyway, the way
an experienced reviewer reads an unfamiliar config file.

Do three things.

BOUNDARIES. Infer trust boundaries from the strings alone. Values like `subnet=private`,
`namespace=clinical`, `vpc_id=...`, `zone=restricted`, `internal=true` place vertices on
one side of a boundary; a crossing is an edge between vertices on different sides. Do not
require a boundary object to exist, because none does.

THREATS. Find paths through the graph where the combination of strings along the path
creates exposure. A threat is a path, not a property of one vertex: an unauthenticated
entry point reaching a component with broad permissions that reads sensitive storage is
one finding, not three. Quote in `evidence` the exact strings that carry the finding, so
a reader can check you. `path` is the vertex sequence.

UNINTERPRETED. List any vertex whose strings you could not reason about, and say why.
Be honest here. An empty list when the graph contains something genuinely opaque is a
worse outcome than admitting the gap, because silent under-reporting is the failure mode
this whole approach exists to avoid."""


def analyse(llm: LLM, topo: Topology) -> dict:
    return llm.json(
        _ANALYSIS_SYSTEM,
        [{"type": "text", "text": json.dumps(topo.payload(), indent=2)}],
        _ANALYSIS_SCHEMA,
    )


# ---------------------------------------------------------------------------
# Audit mode: an enumerable hypothesis space without a component taxonomy.
# ---------------------------------------------------------------------------
#
# The usual objection to replacing a rule engine is that a rule engine can enumerate
# what it considered ("340 rules, here is which fired") and a model cannot.
#
# That is true of the enumeration a rule engine actually performs, which runs over
# COMPONENT TYPES crossed with threat patterns. The component-type axis is open ended
# and proprietary, which is what makes the count a claim about a vendor's inventory
# rather than about the space of threats.
#
# The threat-category axis is not like that. STRIDE is six categories, LINDDUN is
# seven, both are published and stable, and crucially both are independent of
# component type: whether something is subject to spoofing is answerable without
# knowing what it is. So the grid |vertices| x |categories| is fully enumerable, every
# cell gets a decision with reasoning, and negatives are reported rather than implied.
#
# Note what is and is not reintroduced. Threat categories are enumerated. Component
# types are not. The taxonomy this program exists to delete stays deleted.

STRIDE = [
    ("Spoofing", "impersonating something or someone else"),
    ("Tampering", "unauthorised modification of data or code"),
    ("Repudiation", "denying an action without the system being able to prove otherwise"),
    ("Information disclosure", "exposing information to a party not authorised to see it"),
    ("Denial of service", "degrading or denying availability"),
    ("Elevation of privilege", "gaining capability beyond what was granted"),
]

_AUDIT_SCHEMA = {
    "type": "object",
    "properties": {
        "evaluations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "vertex": {"type": "integer"},
                    "category": {"type": "string"},
                    "applies": {"type": "boolean"},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                    "reasoning": {"type": "string"},
                },
                "required": ["vertex", "category", "applies", "evidence", "reasoning"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["evaluations"],
    "additionalProperties": False,
}


def audit(llm: LLM, topo: Topology, categories=STRIDE) -> dict:
    """Decide every cell of vertices x categories, negatives included.

    The output is the artifact an assessor wants: a complete record of what was
    considered, not merely what was found. A rule engine reports the rules that fired
    and is silent about the rest of its own space; this reports every cell.
    """
    cats = "\n".join(f"- {n}: {d}" for n, d in categories)
    system = f"""You are given a directed graph. Vertices are integers with a bag of raw
strings taken verbatim from an infrastructure artifact. There are no types and no schema.

Evaluate EVERY vertex against EVERY category below. Emit one entry per (vertex, category)
pair with no omissions, so a graph of N vertices produces exactly N x {len(categories)}
entries.

{cats}

For each pair set `applies` true or false, quote the exact strings that decided it in
`evidence`, and give one sentence of `reasoning`. A false with reasoning is as valuable
as a true: it is the record that the question was asked and answered.

Where a vertex's strings are unfamiliar, reason from what they assert rather than
declining. If they are genuinely insufficient to decide, set `applies` false and say so
in the reasoning."""

    result = llm.json(
        system,
        [{"type": "text", "text": json.dumps(topo.payload(), indent=2)}],
        _AUDIT_SCHEMA,
        max_tokens=32000,
    )

    # Completeness is checked here, not asserted. A missing cell is a defect in the
    # artifact and the assessor should be told, not left to count rows.
    seen = {(e["vertex"], e["category"]) for e in result["evaluations"]}
    expected = {(v, n) for v in topo.attributes for n, _ in categories}
    result["missing"] = sorted(expected - seen)
    return result


# ---------------------------------------------------------------------------
# Layout. For humans only, and derived from structure alone.
# ---------------------------------------------------------------------------

def layout(topo: Topology, iterations: int = 400, w: float = 900, h: float = 620):
    """Fruchterman-Reingold, 1991. Repulsion between all pairs, attraction along
    edges, temperature annealed to zero.

    The layout reads the edges and nothing else. It does not know and cannot ask what
    any vertex is, which is the point: placement comes from topology, and meaning is
    applied afterwards as styling over the strings.
    """
    n = len(topo.attributes)
    if n == 0:
        return {}
    rng = random.Random(0)  # deterministic, so reruns are diffable
    pos = {v: [rng.uniform(0, w), rng.uniform(0, h)] for v in topo.attributes}
    k = math.sqrt((w * h) / n)
    temp = w / 10

    for _ in range(iterations):
        disp = {v: [0.0, 0.0] for v in pos}
        for v in pos:
            for u in pos:
                if u == v:
                    continue
                dx, dy = pos[v][0] - pos[u][0], pos[v][1] - pos[u][1]
                d = max(math.hypot(dx, dy), 0.01)
                f = (k * k) / d
                disp[v][0] += dx / d * f
                disp[v][1] += dy / d * f
        for a, b in topo.edges:
            if a not in pos or b not in pos:
                continue
            dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
            d = max(math.hypot(dx, dy), 0.01)
            f = (d * d) / k
            disp[a][0] -= dx / d * f
            disp[a][1] -= dy / d * f
            disp[b][0] += dx / d * f
            disp[b][1] += dy / d * f
        for v in pos:
            d = max(math.hypot(*disp[v]), 0.01)
            pos[v][0] = min(w - 40, max(40, pos[v][0] + disp[v][0] / d * min(d, temp)))
            pos[v][1] = min(h - 40, max(40, pos[v][1] + disp[v][1] / d * min(d, temp)))
        temp *= 0.95

    return pos


# A stylesheet over string bags. Add a rule by adding a line; no object model changes,
# because there is no object model. Matching is substring against the raw strings.
STYLESHEET = [
    (("public-read", "0.0.0.0/0", "authorization=NONE", "publicly_accessible=true",
      "just_works", "auth=none"), "#c0392b"),
    (("encrypted=false", "versioning=false", "tls=false", "http://"), "#e67e22"),
    (("subnet=private", "internal=true", "publicly_accessible=false"), "#27ae60"),
]


def style(strings: list[str]) -> str:
    blob = " ".join(strings).lower()
    for needles, colour in STYLESHEET:
        if any(nd.lower() in blob for nd in needles):
            return colour
    return "#5d6d7e"


def to_svg(topo: Topology, pos: dict, path: str) -> None:
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="900" height="620" '
             'viewBox="0 0 900 620"><rect width="900" height="620" fill="#fbfbfc"/>',
             '<defs><marker id="a" markerWidth="9" markerHeight="7" refX="9" refY="3.5" '
             'orient="auto"><polygon points="0 0, 9 3.5, 0 7" fill="#9aa5b1"/></marker>'
             '</defs>']
    for a, b in topo.edges:
        if a in pos and b in pos:
            parts.append(
                f'<line x1="{pos[a][0]:.1f}" y1="{pos[a][1]:.1f}" '
                f'x2="{pos[b][0]:.1f}" y2="{pos[b][1]:.1f}" stroke="#9aa5b1" '
                f'stroke-width="1.4" marker-end="url(#a)"/>')
    for v, (x, y) in pos.items():
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="9" '
                     f'fill="{style(topo.attributes[v])}"/>')
        parts.append(f'<text x="{x:.1f}" y="{y - 15:.1f}" font-size="11" '
                     f'font-family="ui-sans-serif,system-ui" text-anchor="middle" '
                     f'fill="#2c3e50">{topo.labels.get(v, v)}</text>')
    parts.append("</svg>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))


# ---------------------------------------------------------------------------

def report(topo: Topology, result: dict) -> None:
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    print(f"\n{len(topo.attributes)} vertices, {len(topo.edges)} edges\n")

    for b in result.get("boundaries", []):
        members = ", ".join(topo.labels.get(m, str(m)) for m in b["members"])
        print(f"  boundary  {b['label']}: {members}")
        print(f"            evidence: {', '.join(b['evidence'])}")
    print()

    for t in sorted(result.get("threats", []), key=lambda x: sev.get(x["severity"], 9)):
        route = " -> ".join(topo.labels.get(v, str(v)) for v in t["path"])
        print(f"  [{t['severity'].upper()}] {t['title']}")
        print(f"      path: {route}")
        print(f"      evidence: {', '.join(t['evidence'])}")
        print(f"      {t['reasoning']}\n")

    un = result.get("uninterpreted", [])
    if un:
        print("  Uninterpreted (the honesty channel; a library tool reports these as")
        print("  nothing at all):")
        for u in un:
            print(f"      {topo.labels.get(u['vertex'], u['vertex'])}: {u['why']}")
    print()


def report_audit(topo: Topology, result: dict) -> None:
    """Print the full grid. Negatives are the point, so they are not filtered out."""
    evals = result.get("evaluations", [])
    hits = sum(1 for e in evals if e["applies"])
    print(f"\n{len(topo.attributes)} vertices x {len(STRIDE)} categories "
          f"= {len(topo.attributes) * len(STRIDE)} evaluations, "
          f"{len(evals)} returned, {hits} positive\n")

    for v in sorted(topo.attributes):
        print(f"  {topo.labels.get(v, v)}")
        for e in [x for x in evals if x["vertex"] == v]:
            mark = "APPLIES" if e["applies"] else "  ---  "
            print(f"    [{mark}] {e['category']}: {e['reasoning']}")
            if e["evidence"]:
                print(f"              evidence: {', '.join(e['evidence'])}")
        print()

    if result.get("missing"):
        print("  INCOMPLETE. Cells not returned:")
        for v, c in result["missing"]:
            print(f"      {topo.labels.get(v, v)} x {c}")
        print()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--iac", metavar="FILE", help="Terraform or other HCL")
    src.add_argument("--code", metavar="FILE", help="a source file in any language")
    src.add_argument("--image", metavar="FILE", help="an architecture diagram")
    ap.add_argument("--svg", metavar="FILE", help="write a force directed rendering")
    ap.add_argument("--json", metavar="FILE", help="write the raw topology")
    ap.add_argument("--audit", action="store_true",
                    help="enumerate every vertex against every STRIDE category, "
                         "reporting negatives as well as positives")
    ap.add_argument("--extract-only", action="store_true",
                    help="stop after building the topology. With --iac this needs no "
                         "provider, no key and no SDK")
    args = ap.parse_args()

    # HCL extraction is deterministic, so --iac --extract-only needs no provider at
    # all and no key. Code and images need a model to extract; analysis always does.
    needs_model = bool(args.code or args.image) or not args.extract_only
    llm = LLM() if needs_model else None
    if llm:
        print(f"provider -> {llm.describe()}")

    if args.iac:
        with open(args.iac, encoding="utf-8") as f:
            topo = from_iac(f.read())
    elif args.code:
        with open(args.code, encoding="utf-8") as f:
            topo = from_code(llm, f.read())
    else:
        topo = from_image(llm, args.image)

    if not topo.attributes:
        print("Nothing extracted.", file=sys.stderr)
        return 1

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(topo.payload(), f, indent=2)
        print(f"topology -> {args.json}")

    if args.extract_only:
        print(f"\n{len(topo.attributes)} vertices, {len(topo.edges)} edges. "
              f"Analysis skipped.\n")
        for v in sorted(topo.attributes):
            print(f"  {v}  {topo.labels.get(v, v)}")
            print(f"     {topo.attributes[v]}")
    elif args.audit:
        report_audit(topo, audit(llm, topo))
    else:
        report(topo, analyse(llm, topo))

    if args.svg:
        to_svg(topo, layout(topo), args.svg)
        print(f"diagram  -> {args.svg}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
