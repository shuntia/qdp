# qdp — Quake (and Disaster) Datagram Protocol

## Binary Wire Specification — v1.0 (draft)

**Author:** shuntia
**Status:** Draft / implementable

**Scope:**
This document specifies **only** the on-wire binary formats and the **minimum required semantics** to implement packet parsing, integrity & authenticity verification, replay protection, alert propagation, seeding, and relay heartbeats.

## Purpose

The current emergency alert infrastructure, CAP(Common Alert Protocol) is flexible and widely deployed, but they have many flaws including:
- Lack of internationalization
  - Not all people in the affected area are guaranteed to know that language.
- One-to-one
  - One connection means if that single connection fails, CAP will fail to reach the client.
- Too long
  - It may be small enough in terms of the capability of modern infrastructure, but it's too large that TCP/IP will favor to break the data up into multiple packets, and partial loss may render the whole message unusable.
- Unbounded
  - On systems that lack proper amounts of available memory, CAP may overwhelm the chip, given that its length is not hard-capped.
- Concentrated
  - Even though the networking aroud the alert origin may be robust, bottlenecks may exist at any point in between the central origin and client.
  - Physical interruptions of the network may cause a lot of connections to fault, and may require an expensive route change.
  - The amount of connections the origin can juggle simultaneously limits the amount of clients that can receive CAP XML alerts.
- Complex
  - You cannot read information from CAP XML alerts directly, avoiding indirection and full parsing of the tree.
  - XML is hierarchical, and you need to parse the whole tree to fetch information safely.
  - CAP is too flexible and tolerant of duplicate fields in arbitrary order.
  - XML data transmitted by CAP is inherently unordered, requiring traversal to find a specific tag.
  - XML is intended to be markup language for humans, and is hostile against computers.
  - The objective of CAP should be to provide infrastructure information, not directly display raw CAP to the user. It does not make sense that the computer would be able to receive CAP but not have the software to understand what it means.
  - Pushing multimedia through emergency pipelines increases the risk of corruption and/or incomplete messages.
- Slow
  - Current pull-based infrastructure for CAP provides delivery on the scale of minutes.
  - Push-based system uses satellites and takes upwards to 45 seconds to deliver. In many situations you are indoors, thus have a high chance of missing the alert.
- Unsecure
  - No legitimate enforcement on signing.
  - One could theoretically inject an unsigned CAP alert through the system and deliver nationwide panic.
- Demanding
  - Memory requirement is theoretically unbound due to CAP being unbound.
  - Media interpretation requires mature, complex libraries.
  - Realistically requires a whole OS to be running to make use of CAP.

---

## 0. Design Goals

- Minimal alert-plane packet
  - Single UDP datagram
  - Signed, verifiable, immutable

- Best-effort propagation
  - Time-bounded spread
  - Geographic advisory bounds

- Two-plane architecture
  - Alert-plane (UDP): eager, proactive, stateless
  - Info-plane (HTTP/QUIC): lazy, optional (not specified here)

- Compatibility
  - Be easily convertible from existing formats (e.g., CAP)
  - Allow future extensions without breaking existing implementations

- Strong authenticity
  - Alerts are valid **only** if signed by a Regional Origin key
  - Relay “trust” does not imply alert validity

- no_std / zero-copy friendly
  - Fixed layouts
  - Explicit bounds
  - No required allocation

- MTU safety
  - Recommended UDP payload ≤ **1200 bytes**

- Lightweight
  - Be able to run on minimal hardware

All multi-byte integers are **LITTLE-ENDIAN** unless explicitly stated.

---

## 1. Definitions and Conventions

### 1.1 Normative Language

The keywords **MUST**, **SHOULD**, **MAY** are normative.

### 1.2 Versioning

qdp uses a two-level versioning scheme to distinguish wire incompatibility from backward-compatible extensions.

- **Major version (`version_major`)**
  - A change in major version indicates wire-incompatible changes.
  - If `version_major` is greater than the highest version supported by the implementation, the packet **MUST NOT** be fully interpreted.
  - Implementations **MAY** parse only the common prefix for the purposes of safe rejection, logging, or routing, but **MUST** treat the packet as unsupported.
  - No compatibility guarantees are provided across major versions.
  - If `version_major` is zero, the packet is considered invalid.

- **Minor version (`version_minor`)**
  - A change in minor version indicates a backward-compatible extension within the same major version.
  - Minor version updates **MUST NOT** change the meaning of any field defined in the current major version.
  - Minor version updates **MAY**:
    - define new flag bits (previously RESERVED),
    - define new TLV types,
    - define new `hazard_minor` values,
    - add new semantics that can be safely ignored by older implementations.
  - However, keeping up to date is strongly recommended.
  - Receivers **MUST** ignore unknown flag bits and unknown TLV types.

In short:
- **Major version changes break compatibility.**
- **Minor version changes extend behavior without breaking existing implementations.**

### 1.3 Signed vs Unsigned Data
- **Signed region:** all bytes covered by the cryptographic signature.
- **Unsigned tail:** any bytes beyond `header_len`.
  - MUST be ignored for safety-critical decisions.
  - MAY be logged for local diagnostics.

### 1.4 Time
- UNIX seconds (UTC), `u64`.

### 1.5 Geographic Encoding
Latitude and longitude are signed `i32` microdegrees (1e-6 degrees).

Ranges:
- latitude:  −90_000_000 … +90_000_000
- longitude: −180_000_000 … +180_000_000

### 1.6 Distance
Distance is encoded as **10-meter units**:
- Stored value: `radius_10m` (`u16`)
- Real meters: `affected_radius_m = radius_10m × 10`
Advisory only.

### 1.7 Authority Model
- ALERT validity requires:
  1) A valid Ed25519 signature, AND
  2) The signing key being present and authorized in a local Origin Registry (out of scope distribution; registry format defined in §16).
- On-wire packets DO NOT embed public keys in v1.0.
- The packet identifies the signing key by `origin_key_id`.
- `origin_id` is a signed label only and MUST NOT be trusted without external policy.

---

## 2. Common Prefix (All Packets)

**Total size: 55 bytes**

| Offset | Size | Field         | Type    | Description |
|--------|------|---------------|---------|-------------|
| 0x00   | 4    | magic         | u8[4]  | ASCII “QDP1” |
| 0x04   | 1    | version_major | u8     | v1.0 → 1 |
| 0x05   | 1    | version_minor | u8     | v1.0 → 0 |
| 0x06   | 2    | header_len    | u8     | End of signed region |
| 0x0A   | 2    | flags         | u16    | See §3 |
| 0x0C   | 2    | flags_ext     | u16    | MUST be 0 in v1 |
| 0x0F   | 8    | timestamp_s   | u64    | Origin issue time |
| 0x17   | 8    | origin_id     | u64    | Policy-defined label |
| 0x1F   | 16   | event_root_id | u8[16] | Stable event ID |
| 0x2F   | 2    | seq           | u16    | Revision counter |
| 0x31   | 2    | ttl_s         | u16    | MAX_SPREAD_S |
| 0x33   | 4    | reserved1     | u32    | MUST be 0 |
| 0x37   | …    | alert_fields  | —      | ALERT fields (see §4) |

Notes:
- `header_len` MUST be ≤ packet length.
- Bytes beyond `header_len` are **unsigned tail**.

---

## 3. Flags

| Bit | Name       | Meaning |
|-----|------------|--------|
| 0   | PROPAGATE  | Eligible for alert-plane forwarding |
| 1   | URGENT     | Forward with priority |
| 2   | UPDATE     | Revision of existing event |
| 3   | CANCEL     | Cancels an existing event |
| 4   | TEST       | Test alert |
| 5–15 | RESERVED  | MUST be 0 in v1 |

Unknown bits MUST be ignored.

---

## 4. ALERT Packet

### 4.1 Fixed ALERT Fields

| Offset | Size | Field              | Type |
|--------|------|--------------------|------|
| 0x37   | 1    | hazard_major       | u8 |
| 0x38   | 1    | hazard_minor       | u8 |
| 0x39   | 2    | measure            | u16 |
| 0x3B   | 1    | urgency            | u8 |
| 0x3C   | 1    | intensity          | u8 |
| 0x3D   | 1    | certainty          | u8 |
| 0x3E   | 1    | response           | u8 |
| 0x3F   | 8    | onset_s            | u64 |
| 0x47   | 8    | expiry_s           | u64 |
| 0x4F   | 8    | event_time_s       | u64 |
| 0x57   | 4    | epicenter_lat_uDeg | i32 |
| 0x5B   | 4    | epicenter_lon_uDeg | i32 |
| 0x5F   | 2    | radius_10m         | u16 |
| 0x61   | 2    | signed_tlv_len     | u16 |
| 0x63   | 2    | alert_reserved1    | u16 |
| 0x65   | N    | signed_tlv         | bytes |

### 4.2 Signature Block (NO embedded pubkey)

Immediately after `signed_tlv`:

| Field         | Size |
|---------------|------|
| origin_key_id | 8 |
| signature     | 64 |

- Algorithm: **Ed25519 (required)**
- `origin_key_id` identifies a public key in the local Origin Registry (§16).
- Signature signs all bytes from offset `0x00` up to (but excluding) the `signature` field.
  - This includes `origin_key_id`.

`header_len` MUST include the entire signature block and MUST end exactly after the signature field.

---

## 5. Hazard Taxonomy

| hazard_major | hazard_minor | Meaning               |
|--------------|--------------|-----------------------|
| 0            | 0            | RESERVED (invalid)    |
| 1            | 0            | Geophysical Unknown   |
| 1            | 1            | Earthquake            |
| 1            | 2            | Landslide             |
| 2            | 0            | Meteorological Unknown|
| 2            | 1            | Tsunami               |
| 2            | 2            | Storm                 |
| 2            | 3            | Flood                 |
| 3            | 0            | Safety Unknown        |
| 4            | 0            | Security Unknown      |
| 4            | 1            | Terrorism             |
| 4            | 2            | Military Activity     |
| 5            | 0            | Rescue Unknown        |
| 6            | 0            | Fire Unknown          |
| 6            | 1            | Wildfire              |
| 6            | 2            | City Fire             |
| 6            | 3            | Prescribed Fire       |
| 7            | 0            | Health Unknown        |
| 8            | 0            | Environment Unknown   |
| 8            | 1            | Air pollution         |
| 9            | 0            | Transport Unknown     |
| 0x0A         | 0            | Infra Unknown         |
| 0x0B         | 0            | CBRNE Unknown         |
| 0xFF         | 0            | Other (consult TLV)   |

## 6. Event Identity and Updates

- `event_root_id` identifies a physical event.
- `seq` is monotonic per event.

Receiver rules:
- seq < highest_seen → drop
- seq == highest_seen → drop duplicate
- seq > highest_seen → accept update

Replay key tuple:

    (origin_key_id, event_root_id, seq)

---

## 7. Signed TLV Format

TLV layout:
- type: u8
- len:  u8
- val:  u8[len]

Rules:
- Unknown TLVs MUST be ignored.
- TLVs MUST NOT be required for core safety behavior.

TLVs:
- 0x00 UNUSED
- 0x01 HAZARD_NAME (UTF-8)
- 0x02 CAP_ID (UTF-8)
- 0x03 REGION_CODE (u32)
- 0x04 TEXT_SUMMARY (UTF-8)
- 0x05 POLYGON ((i32, i32)[])

---

## 8. Signature Semantics (ALERT)

- Algorithm: **Ed25519 (required)**
- Signed region:
  - All bytes from offset 0x00
  - Up to but excluding the signature field
- `origin_key_id` is included in the signed region.

Authorization and verification (required):
- Receivers MUST resolve `origin_key_id` using the local Origin Registry.
- If `origin_key_id` is unknown or inactive/revoked, the alert MUST be rejected for safety-critical purposes.
- If known, receivers MUST verify the signature using the registry’s `origin_pubkey`.
- Receivers MUST also enforce local policy constraints from the registry entry (hazard/region scopes, etc.).

---

---

## 9. Forwarding Semantics (ALERT)

### 9.1 Time-Based TTL (Canonical v1)

The `ttl_s` field represents **MAX_SPREAD_S**.

Conceptual rule:

    age_s = now_s − timestamp_s
    if age_s > ttl_s → MUST NOT forward

Packets are immutable; relays MUST NOT modify signed bytes.

### 9.2 Geographic Bounding
- Relays SHOULD drop packets outside `radius_10m × 10` meters.
- Backbone relays MAY override.

### 9.3 PROPAGATE Flag
- If unset, packet MUST NOT be forwarded.

### 9.4 Forwarding Strategy
- Stateless fan-out
- Rate-limited
- Random optional jitter

---

## 10. Seeding Model

- Regional Origin signs alerts.
- Data Relay performs first-hop seeding.

Goals:
- Multiple independent entry points
- Delivery over precision

---

## 11. Freshness and Replay Windows

Suggested defaults:
- max_receive_s ≈ 300 seconds
- Replay cache duration ≥ max_receive_s

---

## 12. NAT and Client Constraints

- Leaf clients may not accept inbound UDP.
- Relays SHOULD provide reachable ingress points.
- Client keepalive is out of scope.

---

## 13. Security Notes

- Only authorized origin keys (per local Origin Registry + local policy) can create valid ALERTs.
- Relay compromise cannot forge alerts unless it steals an origin private key.
- Unsigned tail MUST NOT affect decisions.
- Implementations SHOULD rate-limit verification.

---

## 14. Compliance Targets

### Relay MUST
- Bounds-check packets
- Resolve `origin_key_id` via Origin Registry
- Verify signature
- Enforce time-based TTL
- Enforce replay protection
- Forward immutable packets

### Client MUST
- Bounds-check packets
- Resolve `origin_key_id` via Origin Registry
- Verify signature
- Enforce freshness
- Ignore unsigned tail

---

## 15. Reference Sizes (ALERT, no TLV)

- Common prefix: 55 bytes
- ALERT fixed fields: 46 bytes
- Signature block: 72 bytes
- **Total:** 173 bytes

---

## 16. Origin Registry Format (JSON)

This section defines a simple local file format that maps `origin_key_id` → public key and policy constraints.

This file is NOT transmitted on the alert-plane. How it is distributed/updated is out of scope.

### 16.1 Top-level structure

- `format`: string, MUST be `"qdp-origins-1"`
- `generated_at_s`: u64, informational
- `expires_at_s`: u64, informational (0 if none)
- `origins`: array of origin entries

### 16.2 Origin Entry

Each entry MUST contain:
- `origin_key_id`: string (hex `0x...` for u64) OR integer (must fit u64)
- `pubkey_ed25519`: string (base64)
- `status`: `"active"` | `"revoked"` | `"retired"`
- `label`: string (human-readable)
- `scopes`: object describing what this origin is authorized to sign

Recommended `scopes` fields:
- `region_codes`: array of u32 (matches TLV REGION_CODE), or empty for “any”
- `hazard_majors`: array of u8, or empty for “any”
- `hazard_minors`: optional map from major → array of minors (fine-grained allowlist)
- `max_radius_10m`: u16 (0 means “no limit specified”)
- `allow_test`: bool
- `allow_cancel`: bool

### 16.3 Example JSON (base64 pubkeys)

```json
{
  "format": "qdp-origins-1",
  "generated_at_s": 1730000000,
  "expires_at_s": 0,
  "origins": [
    {
      "origin_key_id": "0x1122334455667788",
      "pubkey_ed25519_b64": "qv6sHn...base64...==",
      "status": "active",
      "label": "USGS West Coast (example)",
      "scopes": {
        "region_codes": [ 6, 12 ],
        "hazard_majors": [ 1, 2 ],
        "hazard_minors": { "1": [1,2], "2": [1,2,3] },
        "max_radius_10m": 60000,
        "allow_test": false,
        "allow_cancel": true
      }
    }
  ]
}
```

### 16.4 Required receiver behavior (authorization)
Receivers MUST:
- Reject ALERTs if `origin_key_id` does not exist in the registry OR entry status != `"active"`.
- Verify Ed25519 signature using the registry pubkey.
- Enforce scope rules:
  - If `region_codes` non-empty and packet’s REGION_CODE TLV is present, it MUST be in the allowlist.
  - If `hazard_majors` non-empty, `hazard_major` MUST be in allowlist.
  - If `hazard_minors` present for that major, `hazard_minor` MUST be in allowlist.
  - If `max_radius_10m` non-zero, packet `radius_10m` MUST be ≤ it.
  - If TEST flag set, `allow_test` MUST be true (else reject or suppress per local policy).
  - If CANCEL flag set, `allow_cancel` MUST be true (else reject).

Note: REGION_CODE is optional on-wire. If a deployment requires region constraints, it SHOULD require REGION_CODE TLV presence by local policy.

---

## 17. System Requirements

### 17.1 Minimum System Requirements

- CPU
  - Support for 8-bit pointer arithmetic
- Memory
  - At least 1024 bytes of stack space

### 17.2 Recommended System Requirements

- CPU
  - Support for 16-bit pointer arithmetic
  - Support for large-number arithmetic for Ed25519 verification
- Memory
  - At least 2047 bytes of stack space
  - At least 255 byes of dynamic heap space(Vector TLV storage)

---

## 18. Explicitly Out of Scope

- Info-plane schemas
- Key distribution / revocation mechanisms for the Origin Registry
- Guaranteed delivery
- UI / user policy
- Post-alert TCP chasing

---

**END OF SPEC**


TODO:

List:
- Scheme for updating keys
- 

## X. Public key embedding

- 4 origin pubkeys will be compiled into the binary.
- If the origin key is compromised, they will be rotated out in the next software update.
- In the communication specs, the origin key invalidation scheme will be described in detail.













