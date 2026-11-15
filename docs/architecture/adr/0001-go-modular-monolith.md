# ADR-0001: Go modular monolith for server and agent

* Status: Accepted (2026-11-15)

## Context
The server handles many long-lived WebSocket connections (agents, MeshCentral
control channel, browser live output), CPU-bound crypto (Argon2id, signatures)
and ordinary CRUD. The agent must be a small, dependency-free binary for
Windows (x64, ARM64) and Linux (x64, ARM64) that runs as a service.
Tactical RMM's split across Django, Celery, Redis, NATS and a Go agent is its
largest operational burden.

## Options
* **Go** — static binaries, trivial cross-compilation, mature stdlib for
  HTTP/2, TLS, ACME (`x/crypto/acme/autocert`), WebSockets, Windows services;
  one language for server and agent.
* **Rust** — excellent for the agent, slower iteration for a large CRUD/API
  surface, fewer batteries for the server.
* **TypeScript/Node** — shares a language with the frontend; weaker fit for a
  Windows service agent, single-threaded CPU-bound crypto.
* **Python** — productive for CRUD, poor fit for the agent and for many
  concurrent connections without extra infrastructure.

## Decision
Go for both server and agent. The server is a **modular monolith**: one
process, packages per domain module with explicit interfaces, no internal
brokers. The frontend is built separately and embedded into the server binary.

## Consequences
* One deployable server container plus PostgreSQL and MeshCentral.
* Module boundaries must be enforced by code review and Go `internal`
  packages, not by the network.
* Horizontal scale-out (multiple server replicas) is possible later but needs
  a shared pub/sub for live job output; not required at the target scale.
