"""
firewall_simulator.py

Starter implementation for Firewall Rule Simulation.

Features:
- Packet model (src/dst IP, src/dst port, protocol)
- Rule model (action allow/deny, src/dst net, port ranges, protocol, priority)
- Ordered rule evaluation (first match wins)
- Scenario runner with example scenarios
- CSV/JSON report export
- Simple CLI to run scenarios

How to use:
1. Save this file as `firewall_simulator.py`.
2. Run example scenario: `python firewall_simulator.py --scenario demo1 --out report_demo1.csv`
3. See output CSV/JSON that lists each packet and the matched rule + action.

You can extend by adding more scenarios, a Flask web UI, or unit tests.
"""

import ipaddress
import argparse
import csv
import json
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Union
import datetime

# ----------------------------- Models ---------------------------------

@dataclass
class Packet:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str  # e.g., 'TCP' or 'UDP'

    def to_dict(self):
        return {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'proto': self.proto
        }

@dataclass
class Rule:
    id: str
    action: str  # 'ALLOW' or 'DENY'
    src_net: Optional[str] = None  # CIDR or None
    dst_net: Optional[str] = None
    src_ports: Optional[Union[int, Tuple[int,int]]] = None  # single port or (min,max)
    dst_ports: Optional[Union[int, Tuple[int,int]]] = None
    proto: Optional[str] = None  # 'TCP'/'UDP'/None
    description: Optional[str] = None

    def matches_packet(self, pkt: Packet) -> bool:
        # IP checks
        if self.src_net:
            try:
                net = ipaddress.ip_network(self.src_net)
                if ipaddress.ip_address(pkt.src_ip) not in net:
                    return False
            except ValueError:
                return False
        if self.dst_net:
            try:
                net = ipaddress.ip_network(self.dst_net)
                if ipaddress.ip_address(pkt.dst_ip) not in net:
                    return False
            except ValueError:
                return False

        # Protocol check
        if self.proto and self.proto.upper() != pkt.proto.upper():
            return False

        # Port checks
        if self.src_ports is not None:
            if isinstance(self.src_ports, tuple):
                lo, hi = self.src_ports
                if not (lo <= pkt.src_port <= hi):
                    return False
            else:
                if pkt.src_port != int(self.src_ports):
                    return False

        if self.dst_ports is not None:
            if isinstance(self.dst_ports, tuple):
                lo, hi = self.dst_ports
                if not (lo <= pkt.dst_port <= hi):
                    return False
            else:
                if pkt.dst_port != int(self.dst_ports):
                    return False

        return True

# -------------------------- Rule Engine --------------------------------

class RuleEngine:
    def __init__(self, rules: List[Rule], default_action: str = 'ALLOW'):
        self.rules = rules  # rules are evaluated in order
        self.default_action = default_action

    def evaluate(self, pkt: Packet) -> Tuple[str, Optional[str]]:
        """Return (action, matched_rule_id)"""
        for rule in self.rules:
            if rule.matches_packet(pkt):
                return rule.action.upper(), rule.id
        return self.default_action.upper(), None

# ------------------------- Scenario Runner -----------------------------

class ScenarioRunner:
    def __init__(self, rules: List[Rule], packets: List[Packet], default_action: str = 'ALLOW'):
        self.engine = RuleEngine(rules, default_action=default_action)
        self.packets = packets
        self.results = []

    def run(self):
        now = datetime.datetime.utcnow().isoformat()
        for i, pkt in enumerate(self.packets, start=1):
            action, rule_id = self.engine.evaluate(pkt)
            record = {
                'index': i,
                'timestamp_utc': now,
                **pkt.to_dict(),
                'action': action,
                'matched_rule_id': rule_id
            }
            self.results.append(record)
        return self.results

    def save_csv(self, path: str):
        if not self.results:
            raise RuntimeError('No results to save. Run the scenario first.')
        keys = list(self.results[0].keys())
        with open(path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(self.results)

    def save_json(self, path: str):
        if not self.results:
            raise RuntimeError('No results to save. Run the scenario first.')
        with open(path, 'w') as f:
            json.dump(self.results, f, indent=2)

# ------------------------- Example Scenarios ---------------------------

def example_ruleset_1():
    """Simple ruleset showing port block and subnet allow."""
    return [
        Rule(id='R1', action='DENY', dst_ports=80, proto='TCP', description='Block HTTP'),
        Rule(id='R2', action='ALLOW', src_net='10.0.0.0/24', description='Allow local subnet'),
        Rule(id='R3', action='DENY', dst_ports=(1000,2000), proto='UDP', description='Block UDP high ports')
    ]


def packets_for_demo_1():
    return [
        Packet('10.0.0.5', '8.8.8.8', 12345, 80, 'TCP'),    # from local subnet to HTTP -> R1 matches first -> DENY
        Packet('192.168.1.10', '10.0.0.20', 40000, 22, 'TCP'), # SSH to local -> R2 allows
        Packet('9.9.9.9', '1.1.1.1', 1500, 1500, 'UDP'),       # UDP high port -> R3 DENY
        Packet('10.0.0.8', '8.8.4.4', 33333, 443, 'TCP'),     # local subnet allowed by R2 -> ALLOW
    ]


def example_ruleset_order_test():
    # Show how order matters: general allow placed before a specific deny
    return [
        Rule(id='R1', action='ALLOW', src_net='0.0.0.0/0', description='Allow all (bad order)'),
        Rule(id='R2', action='DENY', dst_ports=22, description='Deny SSH')
    ]


def packets_for_order_test():
    return [
        Packet('8.8.8.8', '1.2.3.4', 55555, 22, 'TCP'),
    ]

# --------------------------- CLI --------------------------------------

def build_args():
    p = argparse.ArgumentParser(description='Firewall Rule Simulator - demo starter')
    p.add_argument('--scenario', choices=['demo1','order_test'], default='demo1', help='Which demo to run')
    p.add_argument('--out', help='Output CSV path (or .json if you prefer).')
    p.add_argument('--default', choices=['ALLOW','DENY'], default='ALLOW', help='Default policy if no rule matches')
    return p.parse_args()


def main():
    args = build_args()
    if args.scenario == 'demo1':
        rules = example_ruleset_1()
        pkts = packets_for_demo_1()
    elif args.scenario == 'order_test':
        rules = example_ruleset_order_test()
        pkts = packets_for_order_test()
    else:
        print('Unknown scenario')
        return

    runner = ScenarioRunner(rules, pkts, default_action=args.default)
    results = runner.run()

    # print summary
    print('Ran scenario:', args.scenario)
    print('Rules:')
    for r in rules:
        print(f'  {r.id}: {r.action} {r.description or ""}')
    print('\nResults:')
    for r in results:
        print(f"#{r['index']} {r['src_ip']}:{r['src_port']} -> {r['dst_ip']}:{r['dst_port']} {r['proto']} => {r['action']} (rule={r['matched_rule_id']})")

    if args.out:
        if args.out.lower().endswith('.json'):
            runner.save_json(args.out)
            print('Saved JSON to', args.out)
        else:
            runner.save_csv(args.out)
            print('Saved CSV to', args.out)

if __name__ == '__main__':
    main()
