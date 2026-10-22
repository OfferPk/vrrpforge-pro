# VRRPForge Pro v1.0.0 — User Guide & NetDevOps Manual

## 1\. Web Studio Quickstart

1. Open `source-code/index.html` in any modern web browser.  
2. Select an industry preset from the top bar:  
   - **Enterprise Core VRRPv3**: Cisco/Arista core deployment with 250ms timers, BFD tracking, upstream WAN tracking (decrement 30), and preempt delay 60s (Grade A+).  
   - **Kubernetes Bare-Metal Kube-VIP**: Linux Keepalived active-passive load balancer VIP with healthcheck tracking scripts (Grade A).  
   - **Fragile Unhardened FHRP**: Unhardened VRRPv2 with mismatched timers, 0s preempt delay, and missing WAN tracking (Grade F).  
3. Review the **10-Point Zero-Trust Scorecard** to evaluate security compliance and review automated remediation recommendations.  
4. Test the **WAN Outage & Failover Simulator**:  
   - Toggle "Simulate Upstream WAN Fiber Cut" to verify whether priority decrement successfully transfers Mastership to the Backup node or triggers a traffic blackhole.  
5. Inspect the **RFC 5798 VRRPv3 Binary Packet Dissector** to review byte offsets and pseudo-header checksum validation.  
6. Export synthesized production configurations for **Cisco IOS-XE**, **Arista EOS**, **Juniper Junos**, **Linux Keepalived**, and **Prometheus**.

---

## 2\. DevSecOps CLI Tool (`vrrpforge-cli.py`)

The standalone Python CLI requires Python 3.8+ and zero third-party dependencies.

### 2.1 Encoding VRRPv3 Advertisements to Binary Hex

python3 build/vrrpforge-cli.py encode \\

  \--version 3 \\

  \--vrid 1 \\

  \--priority 110 \\

  \--vip 10.0.0.254 \\

  \--adver-ms 250

### 2.2 Calculating RFC 5798 Skew Time & Failover Intervals

python3 build/vrrpforge-cli.py timers \\

  \--priority 110 \\

  \--adver-ms 250

Output:

\=== RFC 5798 Convergence & Skew Timer Calculation \===

Advertisement Interval:    250 ms

Router Priority:           110

Calculated Skew Time:      143 ms

Master Down Interval:      893 ms (\~0.893s)

### 2.3 Running Zero-Trust CI/CD Audits

\# Validating production configuration (Exits code 0\)

python3 build/vrrpforge-cli.py audit \-c build/presets/enterprise-core-vrrpv3.json \--strict

\# Validating vulnerable configuration (Exits code 1\)

python3 build/vrrpforge-cli.py audit \-c build/presets/fragile-unhardened-fhrp.json \--strict

---

## 3\. GitHub Actions CI/CD Pipeline Gate

Add this workflow to your NetDevOps repository (`.github/workflows/vrrp-fhrp-gate.yml`):

name: Zero-Trust VRRP & FHRP Gateway Gate

on:

  pull\_request:

    paths:

      \- 'network/vrrp/\*\*'

      \- 'network/gateway/\*\*'

      \- 'keepalived/\*\*'

jobs:

  vrrp-audit:

    runs-on: ubuntu-latest

    steps:

      \- name: Checkout Code

        uses: actions/checkout@v4

      \- name: Set up Python

        uses: actions/setup-python@v5

        with:

          python-version: '3.11'

      \- name: Run VRRPForge Strict Audit Gate

        run: |

          python3 build/vrrpforge-cli.py audit \-c build/presets/enterprise-core-vrrpv3.json \--strict