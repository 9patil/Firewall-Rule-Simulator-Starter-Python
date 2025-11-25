# Firewall Rule Simulator

A small, modular simulator to test firewall allow/deny rules, port blocking, and rule-ordering effects.
Useful for demos, policy validation and learning firewall behaviour.

## Features
- Rules: action (ALLOW/DENY), CIDR src/dst, port or port range, protocol filter
- Ordered evaluation (first-match wins)
- CLI scenario runner + example scenarios
- Simple Flask web UI for interactive runs
- Unit tests with pytest
- Dockerfile for reproducible runs
