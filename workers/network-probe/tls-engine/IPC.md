# TLS engine IPC v1

The engine has no target address, port, DNS resolver or socket. The parent owns
authorization, DNS pinning, STARTTLS, physical budgets and process cancellation.
One process executes one control. It may request sequential connections only.

Every frame has a five-byte header: one unsigned type byte, followed by a
four-byte unsigned big-endian payload length, followed by that many bytes.
There is no newline framing. EOF in a header or payload is a failed invocation.

| Direction | Type | Payload | Meaning |
| --- | --- | --- | --- |
| Child to parent | 1 | empty | CONNECT; each emission consumes one connection attempt |
| Child to parent | 2 | 1..16384 raw bytes | SEND, valid only while connected |
| Child to parent | 3 | 1..262144 UTF-8 bytes | exactly one terminal RESULT matching result.schema.json |
| Child to parent | 4 | empty | CLOSE the current connection |
| Parent to child | 1 | empty | CONNECTED, after pinned socket and STARTTLS are ready |
| Parent to child | 2 | 1..16384 raw bytes | RECEIVED, valid only while connected or draining CLOSE |
| Parent to child | 4 | ASCII enum | CLOSED: eof, timeout, budget, connect_failed, or aborted |
| Parent to child | 5 | empty | ABORT, valid in every nonterminal phase |

No unknown frame type, empty data frame, oversized payload, extra result, or
out-of-phase frame is accepted. After CLOSE, the child drains and counts any
already queued RECEIVED frames until CLOSED. It cannot request another CONNECT
before this barrier. The parent must isolate queued events by socket identity.
Connection failures answer CONNECT with CLOSED, never CONNECTED. ABORT closes
the current connection and permits no subsequent CONNECT or SEND.

Child counters measure TLS bytes crossing this IPC. They exclude STARTTLS and
must not replace the parent's authoritative physical socket counters. The parent
may kill the child independently of child claims, deadlines or framing errors.

Fixed binaries: tls-baseline-legacy, tls-baseline-modern, tls-active-legacy.
Arguments are separate exec arguments, never shell text:

- --control: catalog, handshake, certificate, renegotiation, resumption,
  fallback, compression, heartbleed, robot, ccs.
- --protocol: ssl2, ssl3, tls1, tls1_1, tls1_2, tls1_3.
- --cipher: optional exact compiled-catalog cipher name, at most 96 ASCII
  letters, digits, underscores or hyphens; no cipher-string expressions.
- --group: optional finite group from the capability catalog.
- --hostname: optional canonical ASCII DNS name, at most 253 bytes.
- --alpn: none, http1, h2-http1 (default none).
- --timeout-ms: integer 1..25000 (default 10000).
- --max-connections: integer 1..64 (default 1).
- --trust-bundle: a fixed, parent-owned local trust snapshot path. Never comes
  from a customer, certificate URL, discovery result or remote response.

catalog does not request a connection. It reports only that binary's finite
catalog for the requested protocol. Unsupported controls fail explicitly;
unexecuted/unsupported checks never become negative endpoint evidence.

Linux installs no_new_privs and a syscall allowlist after loading crypto and
trust data. Builds on other operating systems are local test builds and report
sandboxed=false; they cannot be admitted as production scan receipts.
