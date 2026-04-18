# ipqdp — qdp over IP

## IP Transport Specification — v1.0 (draft)

**Author:** shuntia
**Status:** Draft

**Scope:**
This document specifies IP-specific behavior for qdp, including NAT traversal, port binding, client registration, relay heartbeats, and bootstrapping. The qdp wire format is unchanged; this document defines how it is carried over UDP/TCP/IP.

## Purpose

`qdp` itself is not complete without transportation mediums. IP is the most prevalent method of data transportation, so it shall be the main method transporting qdp packets.

## 0. Design Goals

- Provide maximum flexibility with maximum simplicity
  - Balance load

---

## 1. NAT and Client Constraints

- Leaf clients behind NAT may not accept unsolicited inbound UDP.
- Clients MUST use the same socket (and therefore the same source port) for both sending registration packets and receiving alert packets. This ensures the NAT mapping established during registration is the same one used for inbound delivery.
- Relays MUST send alert packets from the same port they receive registration packets on, so the client's NAT mapping remains valid.
- Relays MUST record the source `(ip, port)` of each registration and use it as the alert delivery address.

---


