"""Deterministic event stream: signed envelopes, replay-able topics, and the
stream processor (normalize -> dedup -> policy -> attack detection -> fan-out).

Transport note: envelopes and semantics are broker-agnostic. The shipped
`StreamBus` is a persistent, replay-able, multi-consumer log (JSONL per
topic) that runs in every deployment today; a Kafka deployment uses the same
envelope on the same topic names (see docs/architecture/event-stream.md).
"""
