# qdp — Quake (and Disaster) Datagram Protocol

## JSON Communication Specification — v1.0 (draft)

**Author:** shuntia
**Status:** Draft / implementable

**Scope:**
This document specifies the standard JSON-based communication used by qdp clients to interact with standard qdp alert relays. This documents syncing, and coordination.

---

## 0. Design goals

- Simple, readable, and easy-to-implement JSON messages.

- Guaranteed message delivery with acknowledgments.
  - TCP-based

- Strong trust

- Priming for notification

## 1. Baseline Requirements

- TCP/IP connection support

- Dynamic heap allocation(Optional)

## 2. Required features

