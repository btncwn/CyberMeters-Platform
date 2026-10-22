# Active Check: dns_open_resolver — design

Status: **design only.** This is the first engine for the CI-built network-probe image (#875). No probe code is written until #875 is merged and its deploy secrets exist.

## Purpose

Tell the customer whether a DNS server **they own** answers recursive queries for anyone on the internet. An open resolver is a common misconfiguration: it can be abused to reflect traffic at third parties and it leaks the server's cache.

## Authority and scope

- **Consent:**
  - check id `dns_open_resolver`, per address (`per_address: true`);
  - `isAuthorised(env, { workspaceId, domain, host, check, address })` is asked immediately before each address is checked, and never cached;
  - each result records the `consent_id` and the grant's scope.
- **Targets: only the customer's own DNS hosts** observed in their verified-domain DNS, under the #765 owned-address rule:
  - **included:** nameserver hosts under a verified domain, and their A/AAAA addresses;
  - **excluded:** provider nameservers (for example a DNS host or registrar) and shared infrastructure.
- **No grant, or an address out of scope:** the state is `not_authorised` with the reason code, and nothing is sent.

## What is sent

**Per address, at most two packets:**
1. one standard UDP/53 query;
2. if UDP gives no usable answer, one TCP/53 fallback with the same query.

**The query:**
- type **A** with RD=1;
- for a **CyberMeters-owned test name whose answer is fixed and small** (one A record);
- the address checked is never authoritative for that name.

**Never:**
- ANY, TXT, DNSKEY or other large-response types;
- EDNS buffers above the default;
- repeated or parallel queries to the same address;
- sending to any address the customer has not authorised.

## Result states

| State | Meaning (wording) |
|---|---|
| `open_resolver` | The server returned the correct answer for the test name with RA=1: "answers recursive queries from the internet" |
| `not_recursive` | REFUSED, or no answer for a name it is not authoritative for: "does not answer recursive queries from the internet" |
| `no_response` | No answer on UDP or TCP within the deadline: stated, not concluded |
| `not_authorised` | No grant for this address, or the address is out of scope |

The wording never says "used in attacks", "compromised" or "vulnerable".

## Pipeline

- **Finding:** `dns_open_resolver_reachable`, high, Attack Surface.
- **Registry entry:** "restrict recursion to internal clients, or disable it".
- **Case and alert:** through the existing Attack Surface path, on demand only.
- **Verification:** a later authorised re-check finds `not_recursive`.

## Proof (when built)

- Fixtures for each state.
- Mutants:
  - an answer without RA counted as open;
  - an unauthorised address checked;
  - a large-response type allowed.
- One end-to-end trace.
- Live acceptance on a company-owned resolver only.
