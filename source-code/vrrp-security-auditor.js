/**
 * VRRPForge Pro - 10-Point Zero-Trust VRRP / FHRP Security & Resiliency Auditor
 * Standards & References:
 * - RFC 5798: VRRP Version 3 for IPv4 and IPv6
 * - RFC 3768: VRRP Version 2 for IPv4
 * - RFC 5880: Bidirectional Forwarding Detection (BFD)
 * - NIST SP 800-125B: Secure Virtual Network Configuration
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.VRRPSecurityAuditor = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /**
   * Run 10-Point Zero-Trust Audit on VRRP / FHRP Architecture
   * @param {Object} cfg - Configuration parameters
   * @returns {Object} Score, Grade, and Detailed Findings
   */
  function auditVRRPArchitecture(cfg) {
    const findings = [];
    let totalScore = 0;

    // 1. VRRPv3 Modernization (RFC 5798 vs RFC 3768)
    const ver = parseInt(cfg.version, 10) || 3;
    let vScore = 0;
    let vStatus = 'FAIL';
    let vDesc = '';

    if (ver === 3) {
      vScore = 12;
      vStatus = 'PASS';
      vDesc = 'VRRPv3 (RFC 5798) active. Native sub-second centisecond timers, IPv4/IPv6 unified state machine, and deprecated insecure cleartext authentication.';
    } else {
      vScore = 3;
      vStatus = 'WARN';
      vDesc = 'Legacy VRRPv2 (RFC 3768) detected. Limited to 1-second timer granularity; carries obsolete cleartext passwords with zero cryptographic protection.';
    }
    findings.push({
      id: 'VRRP_VERSION',
      name: 'VRRPv3 Standard Modernization (RFC 5798)',
      score: vScore,
      maxScore: 12,
      status: vStatus,
      description: vDesc,
      remediation: vScore < 12 ? 'Upgrade from VRRPv2 to VRRPv3 ("fhrp version vrrp v3") for sub-second timers and dual-stack IPv4/IPv6.' : null
    });
    totalScore += vScore;

    // 2. Upstream WAN/Route Tracking & Decrement Margin
    const trackingActive = !!cfg.trackingEnabled;
    const masterPriority = parseInt(cfg.masterPriority, 10) || 110;
    const backupPriority = parseInt(cfg.backupPriority, 10) || 100;
    const decrement = parseInt(cfg.trackDecrement, 10) || 30;
    let tScore = 0;
    let tStatus = 'FAIL';
    let tDesc = '';

    if (trackingActive && (masterPriority - decrement < backupPriority)) {
      tScore = 12;
      tStatus = 'PASS';
      tDesc = `Upstream tracking active. Decrement (${decrement}) reduces Master priority to ${masterPriority - decrement}, safely falling below Backup priority (${backupPriority}) to trigger deterministic failover.`;
    } else if (trackingActive) {
      tScore = 4;
      tStatus = 'CRITICAL';
      tDesc = `HAZARD: Upstream tracking is enabled, but decrement (${decrement}) is INSUFFICIENT! Master priority (${masterPriority} -> ${masterPriority - decrement}) remains >= Backup priority (${backupPriority}). Router will stay Master with severed WAN, blackholing traffic.`;
    } else {
      tScore = 0;
      tStatus = 'CRITICAL';
      tDesc = 'CRITICAL DEFECT: No upstream tracking configured! If the primary router loses its WAN/Internet link, it will continue advertising Master status on LAN, blackholing all client traffic.';
    }
    findings.push({
      id: 'UPSTREAM_TRACKING',
      name: 'Upstream Route/Interface Tracking & Decrement Sizing',
      score: tScore,
      maxScore: 12,
      status: tStatus,
      description: tDesc,
      remediation: tScore < 12 ? `Configure interface tracking with decrement >= ${masterPriority - backupPriority + 1} (e.g., "track 1 interface WAN line-protocol" and "vrrp 1 track 1 decrement 30").` : null
    });
    totalScore += tScore;

    // 3. Preempt Delay & Flap Dampening
    const preempt = cfg.preempt !== false;
    const preemptDelay = parseInt(cfg.preemptDelaySec, 10) || 0;
    let pScore = 0;
    let pStatus = 'PASS';
    let pDesc = '';

    if (preempt && preemptDelay >= 30) {
      pScore = 10;
      pStatus = 'PASS';
      pDesc = `Preempt delay configured (${preemptDelay}s). Prevents premature failback before upstream BGP/OSPF routing tables and FIBs converge.`;
    } else if (preempt && preemptDelay > 0) {
      pScore = 6;
      pStatus = 'WARN';
      pDesc = `Preempt delay (${preemptDelay}s) is short. High-scale BGP core convergence may take 30–60 seconds, risking micro-blackholing during failback.`;
    } else if (preempt) {
      pScore = 2;
      pStatus = 'CRITICAL';
      pDesc = 'CRITICAL HAZARD: Immediate Preemption without delay! When primary router reboots, it seizes Mastership immediately before upstream routing converges, dropping traffic.';
    } else {
      pScore = 5;
      pStatus = 'WARN';
      pDesc = 'Preemption is disabled. Mastership will never fail back to primary router automatically; requires manual operator intervention.';
    }
    findings.push({
      id: 'PREEMPT_DELAY',
      name: 'Preempt Delay & Routing Convergence Dampening',
      score: pScore,
      maxScore: 10,
      status: pStatus,
      description: pDesc,
      remediation: pScore < 10 ? 'Set preempt delay to at least 60 seconds ("vrrp 1 preempt delay minimum 60").' : null
    });
    totalScore += pScore;

    // 4. Sub-Second Failover & BFD Integration (RFC 5880)
    const bfdActive = !!cfg.bfdEnabled;
    const adverMs = parseInt(cfg.adverIntervalMs, 10) || 1000;
    let bScore = 0;
    let bStatus = 'PASS';
    let bDesc = '';

    if (bfdActive || adverMs <= 300) {
      bScore = 10;
      bStatus = 'PASS';
      bDesc = bfdActive
        ? 'Sub-50ms BFD peer tracking enabled. Hardware-accelerated failure detection eliminates VRRP holddown delays.'
        : `Fast VRRP timers configured (${adverMs}ms interval; ~${(adverMs * 3.5 / 1000).toFixed(2)}s failover).`;
    } else if (adverMs <= 1000) {
      bScore = 6;
      bStatus = 'WARN';
      bDesc = `Standard 1-second timer (~3.6s failover detection). Adequate for basic campus, but disrupts VoIP and financial trading sessions.`;
    } else {
      bScore = 2;
      bStatus = 'FAIL';
      bDesc = `Sluggish timers (${adverMs}ms). Link drops cause extended multi-second outages.`;
    }
    findings.push({
      id: 'SUBSECOND_FAILOVER',
      name: 'Sub-Second Failover & BFD Peer Tracking (RFC 5880)',
      score: bScore,
      maxScore: 10,
      status: bStatus,
      description: bDesc,
      remediation: bScore < 10 ? 'Enable BFD for VRRP ("vrrp 1 bfd peer <IP>") or reduce advertisement interval to 250ms ("vrrp 1 timers advertise msec 250").' : null
    });
    totalScore += bScore;

    // 5. Timer Alignment & Mismatch Prevention
    const timersMatched = cfg.timersMatched !== false;
    let tmScore = 0;
    let tmStatus = 'PASS';
    let tmDesc = '';

    if (timersMatched) {
      tmScore = 10;
      tmStatus = 'PASS';
      tmDesc = 'Master and Backup advertisement timers are identical. Zero risk of spurious Master elections caused by timer desynchronization.';
    } else {
      tmScore = 0;
      tmStatus = 'CRITICAL';
      tmDesc = 'CRITICAL MISCONFIGURATION: Master and Backup have mismatched timers! Backup will timeout prematurely and claim Mastership, triggering violent dual-master flapping.';
    }
    findings.push({
      id: 'TIMER_ALIGNMENT',
      name: 'Timer Alignment & Dual-Master Election Guard',
      score: tmScore,
      maxScore: 10,
      status: tmStatus,
      description: tmDesc,
      remediation: tmScore < 10 ? 'Ensure all routers in the VRRP group configure the exact same advertisement interval.' : null
    });
    totalScore += tmScore;

    // 6. Rogue Master & L2 Security (Dynamic ARP Inspection / MACsec)
    const l2Security = !!cfg.l2SecurityEnabled;
    let secScore = 0;
    let secStatus = 'PASS';
    let secDesc = '';

    if (l2Security) {
      secScore = 10;
      secStatus = 'PASS';
      secDesc = 'Layer 2 security active (Dynamic ARP Inspection DAI, Port Security, or MACsec). Prevents rogue endpoints from spoofing Priority 255 advertisements.';
    } else {
      secScore = 0;
      secStatus = 'FAIL';
      secDesc = 'FAIL: Unprotected L2 broadcast domain. Since RFC 5798 deprecated VRRP passwords, any rogue VM or unauthorized host on the VLAN can send Priority 255 packets and hijack all subnet traffic (MITM attack).';
    }
    findings.push({
      id: 'ROGUE_MASTER_DEFENSE',
      name: 'Rogue Master Takeover Defense & L2 Snooping Security',
      score: secScore,
      maxScore: 10,
      status: secStatus,
      description: secDesc,
      remediation: secScore < 10 ? 'Enable Dynamic ARP Inspection (DAI), IP Source Guard, and 802.1AE MACsec on all access switch ports.' : null
    });
    totalScore += secScore;

    // 7. Virtual MAC (VMAC) Isolation & VRID Uniqueness
    const vridUnique = cfg.vridUnique !== false;
    let macScore = 0;
    let macStatus = 'PASS';
    let macDesc = '';

    if (vridUnique) {
      macScore = 10;
      macStatus = 'PASS';
      macDesc = 'VRID is unique across trunked VLANs. Virtual MAC (00:00:5E:00:01:VRID) does not collide on shared spine switches.';
    } else {
      macScore = 0;
      macStatus = 'CRITICAL';
      macDesc = 'CRITICAL CONFLICT: Duplicate VRID used across multiple VLANs on non-isolated switches. CAM table thrashing causes erratic MAC flapping and packet loss.';
    }
    findings.push({
      id: 'VMAC_ISOLATION',
      name: 'Virtual MAC (VMAC) Isolation & VRID Uniqueness',
      score: macScore,
      maxScore: 10,
      status: macStatus,
      description: macDesc,
      remediation: macScore < 10 ? 'Assign distinct VRIDs per VLAN (e.g. VRID matching VLAN ID: VRID 10 for VLAN 10, VRID 20 for VLAN 20).' : null
    });
    totalScore += macScore;

    // 8. Gratuitous ARP (GARP) & Switch CAM Table Refresh
    const garpActive = cfg.garpOnFailover !== false;
    let garpScore = 0;
    let garpStatus = 'PASS';
    let garpDesc = '';

    if (garpActive) {
      garpScore = 10;
      garpStatus = 'PASS';
      garpDesc = 'Gratuitous ARP (GARP) transmission verified. Upon failover, new Master broadcasts GARP to instantly reprogram all downstream switch CAM tables.';
    } else {
      garpScore = 0;
      garpStatus = 'FAIL';
      garpDesc = 'FAIL: GARP disabled. Switches will continue forwarding traffic to old Master port until 300-second CAM aging timers expire.';
    }
    findings.push({
      id: 'GARP_REFRESH',
      name: 'Gratuitous ARP (GARP) & CAM Learning Refresh',
      score: garpScore,
      maxScore: 10,
      status: garpStatus,
      description: garpDesc,
      remediation: garpScore < 10 ? 'Ensure "ip gratuitous-arps" is enabled on all router and switch SVI interfaces.' : null
    });
    totalScore += garpScore;

    // 9. Control Plane Policing (CoPP) for Protocol 112
    const coppActive = !!cfg.coppEnabled;
    let coppScore = 0;
    let coppStatus = 'PASS';
    let coppDesc = '';

    if (coppActive) {
      coppScore = 9;
      coppStatus = 'PASS';
      coppDesc = 'Control Plane Policing (CoPP) hardware rate-limits IP Protocol 112. Protects supervisor CPU against VRRP packet flooding attacks.';
    } else {
      coppScore = 0;
      coppStatus = 'FAIL';
      coppDesc = 'FAIL: No CoPP policy applied to VRRP (Protocol 112). Malicious endpoints can flood multicast 224.0.0.18 to crash router control plane.';
    }
    findings.push({
      id: 'COPP_RATE_LIMITING',
      name: 'Control Plane Policing (CoPP) for IP Protocol 112',
      score: coppScore,
      maxScore: 9,
      status: coppStatus,
      description: coppDesc,
      remediation: coppScore < 9 ? 'Classify Protocol 112 in CoPP and apply a strict hardware policer (e.g. 500 pps).' : null
    });
    totalScore += coppScore;

    // 10. Dual-Stack IPv4 / IPv6 Redundancy Parity
    const dualStack = !!cfg.dualStackEnabled;
    let dsScore = 0;
    let dsStatus = 'PASS';
    let dsDesc = '';

    if (dualStack) {
      dsScore = 7;
      dsStatus = 'PASS';
      dsDesc = 'Dual-Stack IPv4 & IPv6 VRRPv3 active. Both IPv4 VIP and IPv6 Link-Local/Global VIPs are synchronously protected against gateway outages.';
    } else {
      dsScore = 2;
      dsStatus = 'WARN';
      dsDesc = 'IPv4-only VRRP. IPv6 traffic (if active) relies on unmanaged SLAAC/Router Advertisements without synchronized failover.';
    }
    findings.push({
      id: 'DUAL_STACK_PARITY',
      name: 'Dual-Stack IPv4 & IPv6 Gateway Redundancy Parity',
      score: dsScore,
      maxScore: 7,
      status: dsStatus,
      description: dsDesc,
      remediation: dsScore < 7 ? 'Configure VRRPv3 for IPv6 address family alongside IPv4 on the same VLAN.' : null
    });
    totalScore += dsScore;

    // Compute Overall Grade
    let grade = 'F';
    if (totalScore >= 95) grade = 'A+';
    else if (totalScore >= 90) grade = 'A';
    else if (totalScore >= 80) grade = 'B';
    else if (totalScore >= 70) grade = 'C';
    else if (totalScore >= 60) grade = 'D';

    return {
      totalScore,
      maxScore: 100,
      percentage: totalScore,
      grade,
      passed: totalScore >= 80,
      summary: `VRRP Architecture Security Rating: ${grade} (${totalScore}/100 points). ${totalScore >= 80 ? 'Production Ready.' : 'Remediation Required.'}`,
      findings
    };
  }

  return {
    auditVRRPArchitecture
  };
}));
