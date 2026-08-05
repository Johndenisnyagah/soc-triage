"""Enrichment: turning incidents into text an analyst can read.

Two halves, and the order between them is the design:

* `summary` is deterministic. No model, no network, no randomness. It is the
  floor -- what ships when the LLM is unavailable, slow, or produces output the
  gate rejects.
* `validation` is the gate that model output must pass before it is allowed to
  replace that floor. Structural checks only; no self-reported confidence is
  read (decision 15).

Nothing here imports an API client, and nothing here builds a prompt. Both are
step 6; this is the part that has to be complete before a prompt is worth
writing.
"""

from __future__ import annotations
