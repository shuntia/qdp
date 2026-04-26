author:
  ins: S. Koga
  name: Shunta Koga
  email: shunta@koga.us
informative:
  CAP:
    title: Common Alerting Protocol Version 1.2
    target: https://docs.oasis-open.org/emergency/cap/v1.2/CAP-v1.2-os.html
    date: 2010
    author:
      -
      ins: J. Westfall
      name: Jacob Westfall
      role: Editor
      -
      ins: E. Jones
      name: Elysa Jones
      org: Warning Systems. Inc.
      -
      org: OASIS
  UDP: RFC0768
  IP: RFC0791
  <!--Maybe add LoRa, TCP, and RFC for network byte order-->
ipr: trust200902

# qdp — Quake (and Disaster) Datagram Protocol

--- abstract

This document describes qdp, a transport-agnostic compact binary wire protocol used for emergency alerts under contrained hardware and lossy networks. It is designed to reach farther and quicker than OASIS {{CAP}}, which tries to deliver full human-readable information at the cost of complexity. It primarily uses fixed fields, with support for TLVs when more expressiveness is required. It also has a mandatory signature to prevent fake alerts propagating through a mesh.

--- middle

# Introduction

The current emergency alert infrastructure, {{CAP}} is flexible and widely deployed, but the structure inherently bears complexity which may fail under extreme conditions such as lossy networks and overloaded devices(i.e. potential outcomes of emergency situations).

This document defines a protocol aimed to be maximally resilient, distributed, and lightweight to mitigate those points.

# 0. Motivation

## 0.1 Issues of Existing Solutions

- Lack of efficient internationalization
  - The size of messages multiply with internationalization.
- Unbounded
  - On systems that lack proper amounts of available memory, CAP may overwhelm the chip, given that its length is not hard-capped.
- Centralized
  - Even though the networking around the alert origin may be robust, bottlenecks may exist at any point in between the central origin and client.
  - Physical interruptions of the network may cause connections to fault, and may require an expensive route change.
  - The amount of connections the origin can juggle simultaneously limits the amount of clients that can receive CAP XML alerts.
- Complex
  - XML is hierarchical, and you need to parse the whole tree to fetch information safely.
  - CAP is too flexible and tolerant of duplicate fields in arbitrary order.
  - Pushing multimedia through emergency pipelines increases the risk of corruption and/or incomplete messages.
- Insecure
  - No legitimate enforcement on signing.
- Demanding
  - Memory requirement is theoretically unbound due to CAP being unbound.
  - Media interpretation requires mature, complex libraries.
  - Realistically requires a whole OS to be running to make use of CAP.

## 0.2 Design Goals

- Minimal alert-plane packet
  - Single UDP datagram
  - Signed, verifiable, immutable

- Best-effort propagation
  - Time-bounded spread
  - Geographic advisory bounds

- Two-plane architecture
  - Alert-plane: eager, proactive, stateless
  - Info-plane: lazy, optional (not specified here)

- Compatibility
  - Be easily convertible from existing formats (e.g., CAP)
  - Allow future extensions without breaking existing implementations

- Strong authenticity
  - Alerts are valid only if signed by a Alert Origin key
  - Relay “trust” does not imply alert validity

- no_std / zero-copy friendly
  - Fixed layouts
  - Explicit bounds
  - No required allocation

- MTU safety
  - Recommended UDP payload ≤ 1200 bytes

- Lightweight
  - Be able to run on minimal hardware

# 1. Definitions and Conventions

## 1.1 Normative Language

{::boilerplate bcp14-tagged}

## 1.2 Versioning

qdp uses a two-level versioning scheme to distinguish wire incompatibility from backward-compatible extensions.

- Major version (`version_major`)
  - A change in major version indicates wire-incompatible changes.
  - If `version_major` is greater than the highest version supported by the implementation, the packet MUST NOT be fully interpreted.
  - Implementations MAY parse only the common prefix for the purposes of safe rejection, logging, or routing, but MUST treat the packet as unsupported.
  - No compatibility guarantees are provided across major versions.
  - If `version_major` is zero, the packet is considered invalid.

- Minor version (`version_minor`)
  - A change in minor version indicates a backward-compatible extension within the same major version.
  - Minor version updates MUST NOT change the meaning of any field defined in the current major version.
  - Minor version updates MAY:
    - define new flag bits (previously RESERVED),
    - define new TLV types,
    - define new `hazard_minor` values,
    - add new semantics that can be safely ignored by older implementations.
  - However, keeping up to date is strongly recommended.
  - Receivers MUST ignore unknown flag bits and unknown TLV types.

## 1.3 Time

- UNIX seconds (UTC), `u64`.
- Method of syncing time is dependent on hardware and medium.

## 1.4 Geographic Encoding

Latitude and longitude are signed `i32` microdegrees (1e-6 degrees).

Ranges:

- latitude: −90_000_000 … +90_000_000
- longitude: −180_000_000 … +180_000_000

## 1.5 Distance

Distance is encoded as 10-meter units:

- Stored value: `radius_10m` (`u16`)
- Real meters: `affected_radius_m = radius_10m × 10`
- Used for propagation decisions (see §8.2)
- A value of 0 indicates "unknown" or "see polygon TLV"

## 1.6 Authority Model

- ALERT validity requires:
  1. A valid Ed25519 signature, AND
  2. The signing key being present in the local Origin Registry (registry format defined in §17).
- On-wire packets DO NOT embed public keys in v1.0.
- The packet identifies the signing key by `origin_key_id`.



# 2. Common Prefix (All Packets)

Total size: 8 bytes

| Offset | Size | Field         | Type  | Description               |
| ------ | ---- | ------------- | ----- | ------------------------- |
| 0x00   | 4    | magic         | u8[4] | ASCII “QDP1”              |
| 0x04   | 1    | version_major | u8    | v1.0 → 1                  |
| 0x05   | 1    | version_minor | u8    | v1.0 → 0                  |
| 0x06   | 2    | flags         | u16   | See §3                    |
| 0x08   | …    | payload       | -     | ALERT or non-ALERT fields |

Notes:

- The signed region is `[0x00, packet_len − 64)` for signed packets.
- The signature is always the last 64 bytes of signed packets.



# 3. Flags

Bit numbering: Bit 0 is the most significant bit (MSB).

| Bit  | Name      | Meaning                                    |
| ---- | --------- | ------------------------------------------ |
| 0    | ALERT     | This is an ALERT packet                    |
| 1    | URGENT    | Forward with priority                      |
| 2    | UPDATE    | Revision of existing event                 |
| 3    | CANCEL    | Cancels an existing event                  |
| 4    | TEST      | Test alert                                 |
| 5–15 | RESERVED  | Unused in v1; MUST be ignored by receivers |



# 4. ALERT Packet

## 4.1 Fixed ALERT Fields

| Offset | Size | Field              | Type  |
| ------ | ---- | ------------------ | ----- |
| 0x08   | 8    | timestamp_s        | u64   |
| 0x10   | 4    | event_id           | u32   |
| 0x14   | 2    | seq                | u16   |
| 0x16   | 2    | ttl_s              | u16   |
| 0x18   | 1    | hazard_major       | u8    |
| 0x19   | 1    | hazard_minor       | u8    |
| 0x1A   | 1    | urgency            | u8    |
| 0x1B   | 1    | severity           | u8    |
| 0x1C   | 1    | certainty          | u8    |
| 0x1D   | 1    | response           | u8    |
| 0x1E   | 8    | onset_s            | u64   |
| 0x26   | 8    | expiry_s           | u64   |
| 0x2E   | 8    | effective_time_s   | u64   |
| 0x36   | 4    | epicenter_lat      | i32   |
| 0x3A   | 4    | epicenter_lon      | i32   |
| 0x3E   | 2    | radius_10m         | u16   |
| 0x40   | N    | signed_tlv         | bytes |

Field descriptions:

- `timestamp_s`: The time this alert was issued
- `event_id`: The root ID that this event has. Subsequent updates or queries to a database will utilze this specific key.
- `ttl_s`: The baseline amount of time relays SHOULD propagate for.
- `hazard_major`, `hazard_minor`, `urgency`, `certainty`, `response`: Specified in §5.
- `onset_s`: When the alert becomes active
- `expiry_s`: When the alert expires
- `effective_time_s`: When the event actually occurred or will occur
- `epicenter_lat`, `epicenter_lon`: The latitude and longitude of the epicenter, divided by 1e7.
- `radius_10m`: Affected radius used for propagation decisions (see §8.2)

Deriving signed_tlv bounds:
The signed TLV block has no explicit length field. Bounds are derived from the transport-provided packet length:

- `signed_tlv` starts at offset `0x40`
- `signed_tlv` ends at `packet_len − 68` (68 = 4 origin_key_id + 64 signature)
- Receivers MUST validate: `packet_len ≥ 0x40 + 68` (i.e., `packet_len ≥ 132`)

## 4.2 Signature Block

Immediately follows `signed_tlv`:

| Field         | Size | Description                                             |
| ------------- | ---- | ------------------------------------------------------- |
| origin_key_id | 4    | Identifies the signing key in the Origin Registry (§17) |
| signature     | 64   | Ed25519 signature                                       |

- Algorithm: Ed25519 (required)
- Signed region: `[0x00, packet_len − 64)` — covers Common Prefix + ALERT fields + signed_tlv + origin_key_id.
- Receivers MUST resolve `origin_key_id` via the Origin Registry and reject if not present.
- Receivers MUST verify the signature before acting on any ALERT field.

# 5. Value Tables

These list the possible values for fields in qdp ALERT packets. Most fields are designed to reflect CAP.
For advanced meanings of these values, refer to the OASIS {{CAP}} specs §3.2.2.

NOTE: additional `hazard_minor` values are to be determined. Should be able to convert from all preexisting CAP messages which have been produced using this table.

## 5.1 Hazard tables

| hazard_major | hazard_minor | Meaning                |
| ------------ | ------------ | ---------------------- |
| 0            | 0            | RESERVED (invalid)     |
| 1            | 0            | Geophysical Unknown    |
| 1            | 1            | Earthquake             |
| 1            | 2            | Landslide              |
| 1            | 3            | Tsunami                |
| 2            | 0            | Meteorological Unknown |
| 2            | 1            | Storm                  |
| 2            | 2            | Flood                  |
| 3            | 0            | Safety Unknown         |
| 4            | 0            | Security Unknown       |
| 4            | 1            | Terrorism              |
| 4            | 2            | Military Activity      |
| 5            | 0            | Rescue Unknown         |
| 6            | 0            | Fire Unknown           |
| 6            | 1            | Wildfire               |
| 6            | 2            | City Fire              |
| 6            | 3            | Prescribed Fire        |
| 7            | 0            | Health Unknown         |
| 8            | 0            | Environmental Unknown  |
| 8            | 1            | Air pollution          |
| 9            | 0            | Transport Unknown      |
| 0x0A         | 0            | Infra Unknown          |
| 0x0B         | 0            | CBRNE Unknown          |
| 0xFF         | 0            | Other                  |

## 5.2 Response

| Value | Meaning           |
| ----- | ----------------- |
| 0     | RESERVED(invalid) |
| 1     | All Clear         |
| 2     | Assess            |
| 3     | Avoid             |
| 4     | Evacuate          |
| 5     | Execute           |
| 6     | Monitor           |
| 7     | Prepare           |
| 8     | Shelter           |
| 9     | None              |

## 5.3 Urgency

| Value | Meaning           |
| ----- | ----------------- |
| 0     | RESERVED(invalid) |
| 1     | Expected          |
| 2     | Future            |
| 3     | Immediate         |
| 4     | Past              |
| 5     | Unknown           |

## 5.4 Severity

| Value | Meaning           |
| ----- | ----------------- |
| 0     | RESERVED(invalid) |
| 1     | Extreme           |
| 2     | Minor             |
| 3     | Moderate          |
| 4     | Severe            |
| 5     | Unknown           |

## 5.5 Certainty

| Value | Meaning           |
| ----- | ----------------- |
| 0     | RESERVED(invalid) |
| 1     | Likely            |
| 2     | Observed          |
| 3     | Possible          |
| 4     | Unlikely          |
| 5     | Unknown           |

# 6. Event Identity and Updates

- `event_id` identifies a physical event.
- `seq` is monotonic per event, starting from 0.
- `seq` MUST NOT overflow. In the case `seq` reaches 65535, the origin MUST re-issue an alert with a REPLACES TLV, and that alert SHOULD be URGENT.

Receiver rules:

- seq < highest_seen → drop
- seq == highest_seen → drop duplicate
- seq > highest_seen → accept update, advance highest_seen

Deduplication state per event:

    (origin_key_id, event_id) → highest_seq: u16

## 6.1 CANCEL Semantics

A packet with the CANCEL flag set cancels the event identified by `event_id`.

- CANCEL packets MUST carry a `seq` strictly greater than the highest previously accepted `seq` for that event.
- Upon accepting a CANCEL, receivers MUST immediately expire the event and cease acting on it.
- The CANCEL's deduplication entry MUST persist in the replay cache for at least `ttl_s` seconds measured from the CANCEL packet's own `timestamp_s`. This prevents late-arriving retransmissions of the original alert from slipping through after the CANCEL entry expires.

# 7. Signed TLV Format

TLV layout:

- type: u8
- len: u8
- val: u8[len]

Rules:

- Unknown TLVs MUST be ignored.
- TLVs MUST NOT be required for core safety behavior.

TLVs:

- 0x00 UNUSED
- 0x01 HAZARD_NAME (UTF-8)
- 0x02 POLYGON ((i32, i32)[])
  - POLYGON MUST contain no less than 3 points and no more than 8 points.
  - POLYGON points MUST be closed, and MUST be ordered in a counterclockwise fashion.
  - POLYGON points MUST be the latitude and longitude of the point divided by 1e7.
- 0x03 REPLACES (u32[])
  - This is for when an alert origin issues an alert which may replace another for a variety of reasons, such as prevention of `seq` overflow, merging of two alerts, etc. An alert replacing another SHOULD be marked as URGENT.

# 8. Forwarding Semantics (ALERT)

## 8.1 Time-Based TTL

The `ttl_s` field represents how many seconds the packet is permitted to spread.

Conceptual rule:

    age_s = now_s − timestamp_s
    if age_s > ttl_s → SHOULD NOT forward

## 8.2 Geographic Bounding

- Relays SHOULD drop packets outside `radius_10m × 10` meters.
  - If a relay does not know its own location, it MUST propagate.

## 8.3 Forwarding Strategy

- Stateless fan-out
- Medium-dependent congestion control

## 8.4 Forwarding exceptions

Under any of the conditions specified below, alerts MAY be propagated regardless of ttl and geographic bounding.

- When a relay has a record of that specific event ID in its cache and it receives an alert with higher `seq`.
- When a relay is unsure of its own time, or if it may have a skewed clock for any reason.
- When a transport medium is known to have a slow transport speed.

# 9. Non-ALERT packets

## 9.1 Fixed headers

| Offset | Size | Field           | Type |
| ------ | ---- | --------------- | ---- |
| 0x08   | 2    | kind            | u16  |
| 0x0A   | …    | general payload | -    |

The `kind` field identifies the packet type. All non-ALERT packets share this header immediately after the Common Prefix.

Receivers MUST silently drop any packet whose `kind` is unknown or whose `kind` belongs to a different transport's range.

## 9.2 qdp Reserved Ranges

The table of reservations for qdp 1.0 is as follows.

| Range/Value   | Category          |
| ------------- | ----------------- |
| 0x0000        | RESERVED(invalid) |
| 0x0001-0x00FF | qdp               |
| 0x0100-0x01FF | ipqdp             |
| 0x0200-0xFEFF | Future use        |
| 0xFF00-0xFFFE | Private use       |
| 0xFFFF        | RESERVED(invalid) |

# 10. Non-ALERT reserved packet kinds

All packets with `kind` in the qdp core range (0x0001–0x00FF) are master origin advisories and MUST be signed by the compiled-in master origin key(distribution is out of band, and master key rotation will need an update). Signing is determined by `kind`, not by a flag.

Receivers MUST:

- Verify the Ed25519 signature over the signed region `[0x00, packet_len − 64)`.
- Drop the packet if verification fails.
- Drop the packet if `kind` is unknown.

## Advisory Signature Block

Immediately follows the kind-specific payload:

| Field     | Size | Description                                      |
| --------- | ---- | ------------------------------------------------ |
| signature | 64   | Ed25519 signature over `[0x00, packet_len − 64)` |

## Advisory Kind Assignments

| Kind   | Name                      |
| ------ | ------------------------- |
| 0x0001 | ADVISORY_NEW              |
| 0x0002 | ADVISORY_REVOKE           |
| 0x0003 | ADVISORY_RETIRE           |
| 0x0004 | ADVISORY_UPDATE           |
| 0x0005 | ADVISORY_REGISTRY_REFRESH |

## 10.1 ADVISORY_NEW (0x0001)

Registers a new alert origin. Receivers MUST add the entry to their local registry and update their stored registry version to `new_registry_version`. In the case nodes receive a valid ADVISORY_NEW packet that collides with the current registry, nodes MUST drop that packet and refuse update, and SHOULD do a full resync of its local origin registry.

| Offset | Size | Field                | Type   |
| ------ | ---- | -------------------- | ------ |
| 0x0A   | 8    | new_registry_version | u64    |
| 0x12   | 4    | origin_key_id        | u32    |
| 0x16   | 32   | pubkey_ed25519       | u8[32] |

Minimum packet size: 8 (prefix) + 2 (kind) + 44 (payload) + 64 (signature) = 118 bytes

## 10.2 ADVISORY_REVOKE (0x0002)

Emergency revocation of a compromised or rogue alert origin. Receivers MUST immediately remove the identified origin from their local registry and reject any further ALERTs signed by it, regardless of signature validity.

This packet SHOULD have URGENT and PROPAGATE set to 1.

| Offset | Size | Field                | Type |
| ------ | ---- | -------------------- | ---- |
| 0x0A   | 8    | new_registry_version | u64  |
| 0x12   | 4    | origin_key_id        | u32  |

Minimum packet size: 8 + 2 + 12 + 64 = 86 bytes

## 10.3 ADVISORY_RETIRE (0x0003)

Planned decommission of an alert origin. Receivers MUST remove the identified origin from their local registry and update their stored registry version.

Unlike ADVISORY_REVOKE, retirement is planned and does not imply compromise. URGENT SHOULD NOT be set.

| Offset | Size | Field                | Type |
| ------ | ---- | -------------------- | ---- |
| 0x0A   | 8    | new_registry_version | u64  |
| 0x12   | 4    | origin_key_id        | u32  |

Minimum packet size: 86 bytes

## 10.4 ADVISORY_UPDATE (0x0004)

Notifies nodes of a scheduled qdp protocol update. This is advisory only — implementations MAY ignore it. It carries no enforcement.

| Offset | Size | Field              | Type |
| ------ | ---- | ------------------ | ---- |
| 0x0A   | 1    | version_major      | u8   |
| 0x0B   | 1    | version_minor      | u8   |
| 0x0C   | 8    | scheduled_update_s | u64  |

Minimum packet size: 8 + 2 + 10 + 64 = 84 bytes

## 10.5 ADVISORY_REGISTRY_REFRESH (0x0005)

Signals that the registry has been updated and nodes SHOULD re-sync via the info-plane. Carries the authoritative current registry version so receivers can determine whether they are behind.

| Offset | Size | Field                    | Type |
| ------ | ---- | ------------------------ | ---- |
| 0x0A   | 8    | current_registry_version | u64  |

Receivers that find their local registry version behind `current_registry_version` SHOULD fetch the full registry from the info-plane.

Minimum packet size: 8 + 2 + 8 + 64 = 82 bytes

# 11. Seeding Model

- Alert Origin: signs and issues ALERT packets.
- Data Relay: receives alerts from Alert Origins and performs first-hop seeding into the mesh.

Goals:

- Multiple independent entry points into the mesh
- Delivery over precision — best-effort propagation is preferred over guaranteed delivery

All alert-plane propagation from Alert Origins MUST pass through at least one Data Relay before reaching leaf clients. General qdp coordination packets MAY originate from any node. Transport-specific seeding rules (relay discovery, registration, forwarding topology) are defined in per-transport specifications. See ipqdp.

# 12. Freshness and Replay Windows

REQUIRED cache length:

- Replay cache duration ≥ ttl_s

# 13. Transport Constraints

Transport-specific constraints such as NAT traversal, port binding, and client keepalive are defined in per-transport specifications.

# 14. Compliance Targets

## Relay MUST

- Bounds-check packets
- Resolve `origin_key_id` via Origin Registry
- Verify signature
- Enforce time-based TTL
- Enforce replay protection
- Forward immutable packets

## Client MUST

- Bounds-check packets
- Resolve `origin_key_id` via Origin Registry
- Verify signature
- Enforce freshness

# 15. Reference Sizes (ALERT, no TLV)

- Common prefix: 8 bytes
- ALERT fixed fields: 56 bytes
- Signature block: 68 bytes
- Total: 132 bytes

# 16. Origin Registry Format

This section defines a simple local file or in-memory region that maps `origin_key_id` → public key.

This file is NOT transmitted on the alert-plane. How it is distributed/updated is out of scope.

## 16.1 Top-level structure

- `registry_version`: u64, used to manage deltas and versions. This MUST match the newest version that the node has obtained, either via a sync or ADVISORY.

## 16.2 Origin Entry

Each entry MUST contain:

- `origin_key_id`: integer (must fit u32)
- `pubkey`: Raw Ed25519 public key (32 bytes)

## 16.3 Required receiver behavior (authorization)

Receivers MUST:

- Reject ALERTs if `origin_key_id` does not exist in the registry.
- Verify Ed25519 signature using the registry pubkey.
- Remove origins immediately upon receiving a valid ADVISORY_REVOKE or ADVISORY_RETIRE signed by the master origin.

# 17. Mesh Isolation

Although qdp alerts are made to be usable in any region, nations SHOULD isolate their mesh against potential attacks by neighboring nations via a false alert. In such cases, nations SHOULD compile in their own keys for their nation, and isolate their trust system.

# 18. Transportation and auxiliary infrastructure

qdp only declares the common protocol which all devices using qdp must be able to parse. Therefore info-plane schemas, key distribution, and propagation will be medium-dependent.
There are other specifications that are dependent on the medium, such as:

  - ipqdp: a mesh propagation network over TCP/UDP/IP. Defines HELLO, RESYNC, and other IP-specific behavior. The primary distribution method.
  - loraqdp: qdp over raw LoRa radio. Targets long-range, low-bandwidth deployment on constrained hardware.

Other mediums may distribute qdp natively with medium-specific framing. The auxiliary data may change, but the qdp packet itself will be preserved.

# Security Considerations

The security and validity of qdp effectively relies on a single master key, which should be kept airtight, preferably using an HSM or equivalent security measure. If the master key is compromised, then a large-scale firmware update would be necessary for resetting keys.
<!--I might add an ADVISORY_MASTER that has a ROOT key. That's for tomorrow, I guess.-->
Alert origins should keep their private keys secure, but in the case of a compromise, the master key should be able to revoke the compromised key fairly quickly.
Malicious alert relays will not be able to issue alerts or affect another node unless they have a origin private key, and complying implementations will be able to drop invalid packets either forged by a node or replayed from a previous time.
A malicious fleet of relays can "dilute" the mesh depending on the medium. On mediums such as IP, if a fleet of relays register but drop packets on a real emergency alert, they may degrade the resilience of the network.

# IANA Considerations

This document has no IANA actions.
