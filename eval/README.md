# Evaluation

    python eval/run_eval.py            # writes eval/results.md

## Sample format (`samples.jsonl`, one JSON object per line)

| field | meaning |
|---|---|
| `id` | unique id, e.g. `ri-06` |
| `category` | `description_poisoning`, `result_injection`, `exfil_chain` or `benign` |
| `surface` | where the content is fed in: `description`, `result` or `chain` |
| `malicious` | `true` if the guard should stop it, `false` if it should let it through |
| `content` | see below |
| `note` | free text: what this sample is meant to test |

`content` by surface:

- `description`: a string (used as the tool's description) **or** a full tool definition
  object (`{"name": ..., "description": ..., "inputSchema": ...}`) when the attack sits
  in a parameter description.
- `result`: a string, the text a tool returned. Optional extra field `tool`
  (default `web.fetch`) sets which tool it came from.
- `chain`: `{"steps": [...]}`. Each step is `{"tool": "server.tool", "result": "..."}`
  (a tool returned this) or `{"tool": "server.tool", "arguments": {...}}` (the agent
  now tries this call). Tool names are matched against `eval/policy.yaml`.

A sample counts as **blocked** if the guard removed the tool, withheld a result, or held a call.

## Adding samples

Append lines to `samples.jsonl`. The seed set has 5 samples per category and was written
by the same person who wrote the rules, so its numbers are optimistic for `rules`.
Samples from other sources (published injection corpora, your own red-teaming) are what
make the numbers meaningful. Do not edit a sample because a detector gets it wrong:
misses and false positives are listed in the report on purpose.
