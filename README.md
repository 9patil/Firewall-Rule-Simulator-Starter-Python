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

## Repo layout
firewall-sim/
├─ README.md
├─ requirements.txt
├─ Dockerfile
├─ firewall_sim/
│ ├─ init.py
│ ├─ models.py
│ ├─ engine.py
│ ├─ runner.py
│ ├─ examples.py
│ ├─ cli.py
│ └─ webui.py
├─ tests/
│ ├─ test_rule_matching.py
│ └─ test_scenario_runner.py
└─ examples/
├─ demo1.json



