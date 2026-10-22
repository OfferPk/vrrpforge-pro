/**
 * VRRPForge Pro - Web Application Controller
 */

(function () {
  'use strict';

  // Industry Presets
  const PRESETS = {
    enterprise: {
      name: 'Enterprise Core VRRPv3 (Cisco/Arista)',
      vrid: 1,
      version: 3,
      vip: '10.0.0.254',
      primaryIp: '10.0.0.1',
      netmask: '255.255.255.0',
      cidr: '24',
      masterPriority: 110,
      backupPriority: 100,
      adverIntervalMs: 250,
      vlan: 100,
      wanInterface: 'TenGigabitEthernet0/0/1',
      trackingEnabled: true,
      trackDecrement: 30,
      preempt: true,
      preemptDelaySec: 60,
      bfdEnabled: true,
      timersMatched: true,
      l2SecurityEnabled: true,
      vridUnique: true,
      garpOnFailover: true,
      coppEnabled: true,
      dualStackEnabled: true,
      simulateWanDrop: false
    },
    k8s: {
      name: 'Kubernetes Bare-Metal Kube-VIP (Keepalived)',
      vrid: 50,
      version: 3,
      vip: '192.168.10.100',
      primaryIp: '192.168.10.11',
      netmask: '255.255.255.0',
      cidr: '24',
      masterPriority: 120,
      backupPriority: 100,
      adverIntervalMs: 500,
      vlan: 50,
      lanInterface: 'eth0',
      wanInterface: 'eth1',
      trackingEnabled: true,
      trackDecrement: 40,
      preempt: true,
      preemptDelaySec: 30,
      bfdEnabled: false,
      timersMatched: true,
      l2SecurityEnabled: true,
      vridUnique: true,
      garpOnFailover: true,
      coppEnabled: true,
      dualStackEnabled: false,
      simulateWanDrop: false
    },
    fragile: {
      name: 'Fragile Unhardened FHRP',
      vrid: 1,
      version: 2,
      vip: '172.16.1.1',
      primaryIp: '172.16.1.2',
      netmask: '255.255.255.0',
      cidr: '24',
      masterPriority: 105,
      backupPriority: 100,
      adverIntervalMs: 1000,
      vlan: 1,
      wanInterface: 'GigabitEthernet0/1',
      trackingEnabled: false,
      trackDecrement: 0,
      preempt: true,
      preemptDelaySec: 0,
      bfdEnabled: false,
      timersMatched: false,
      l2SecurityEnabled: false,
      vridUnique: false,
      garpOnFailover: false,
      coppEnabled: false,
      dualStackEnabled: false,
      simulateWanDrop: true
    }
  };

  let activeTab = 'cisco';

  // DOM Elements
  const elVrid = document.getElementById('input-vrid');
  const elVersion = document.getElementById('select-version');
  const elVip = document.getElementById('input-vip');
  const elPrimaryIp = document.getElementById('input-primary-ip');
  const elMasterPriority = document.getElementById('input-master-priority');
  const elBackupPriority = document.getElementById('input-backup-priority');
  const elAdverMs = document.getElementById('input-adver-ms');
  const elVlan = document.getElementById('input-vlan');
  const elBadgeVmac = document.getElementById('badge-vmac');

  const elChkTracking = document.getElementById('chk-tracking');
  const elTrackDecrement = document.getElementById('input-track-decrement');
  const elWanIface = document.getElementById('input-wan-iface');
  const elChkPreempt = document.getElementById('chk-preempt');
  const elPreemptDelay = document.getElementById('input-preempt-delay');
  const elChkBfd = document.getElementById('chk-bfd');
  const elChkTimersMatched = document.getElementById('chk-timers-matched');
  const elChkL2Sec = document.getElementById('chk-l2-security');
  const elChkCopp = document.getElementById('chk-copp');
  const elChkDualStack = document.getElementById('chk-dual-stack');

  const elChkWanDrop = document.getElementById('chk-simulate-wan-drop');
  const elFailoverStatus = document.getElementById('badge-failover-status');
  const elActiveNode = document.getElementById('input-active-node');
  const elTrackingExplanation = document.getElementById('tracking-explanation');

  const elValAdverTime = document.getElementById('val-adver-time');
  const elValSkewTime = document.getElementById('val-skew-time');
  const elValMasterDown = document.getElementById('val-master-down');
  const elValFailoverWindow = document.getElementById('val-failover-window');

  const elScoreBanner = document.getElementById('score-banner');
  const elScoreGrade = document.getElementById('score-grade');
  const elScoreTitle = document.getElementById('score-title');
  const elScoreSummary = document.getElementById('score-summary');
  const elFindingsContainer = document.getElementById('findings-container');

  const elBadgePacketProto = document.getElementById('badge-packet-proto');
  const elPacketHexDump = document.getElementById('packet-hex-dump');
  const elSynthOutput = document.getElementById('synth-output');
  const elBtnCopy = document.getElementById('btn-copy-config');

  function getFormConfig() {
    return {
      vrid: parseInt(elVrid.value, 10) || 1,
      version: parseInt(elVersion.value, 10) || 3,
      vip: elVip.value.trim(),
      primaryIp: elPrimaryIp.value.trim(),
      netmask: '255.255.255.0',
      cidr: '24',
      masterPriority: parseInt(elMasterPriority.value, 10) || 110,
      backupPriority: parseInt(elBackupPriority.value, 10) || 100,
      adverIntervalMs: parseInt(elAdverMs.value, 10) || 250,
      vlan: parseInt(elVlan.value, 10) || 100,
      wanInterface: elWanIface.value.trim(),
      trackingEnabled: elChkTracking.checked,
      trackDecrement: parseInt(elTrackDecrement.value, 10) || 30,
      preempt: elChkPreempt.checked,
      preemptDelaySec: parseInt(elPreemptDelay.value, 10) || 0,
      bfdEnabled: elChkBfd.checked,
      timersMatched: elChkTimersMatched.checked,
      l2SecurityEnabled: elChkL2Sec.checked,
      vridUnique: true,
      garpOnFailover: true,
      coppEnabled: elChkCopp.checked,
      dualStackEnabled: elChkDualStack.checked,
      simulateWanDrop: elChkWanDrop.checked
    };
  }

  function applyPreset(presetKey) {
    const p = PRESETS[presetKey];
    if (!p) return;

    elVrid.value = p.vrid;
    elVersion.value = p.version;
    elVip.value = p.vip;
    elPrimaryIp.value = p.primaryIp;
    elMasterPriority.value = p.masterPriority;
    elBackupPriority.value = p.backupPriority;
    elAdverMs.value = p.adverIntervalMs;
    elVlan.value = p.vlan;
    elWanIface.value = p.wanInterface;
    elChkTracking.checked = p.trackingEnabled;
    elTrackDecrement.value = p.trackDecrement;
    elChkPreempt.checked = p.preempt;
    elPreemptDelay.value = p.preemptDelaySec;
    elChkBfd.checked = p.bfdEnabled;
    elChkTimersMatched.checked = p.timersMatched;
    elChkL2Sec.checked = p.l2SecurityEnabled;
    elChkCopp.checked = p.coppEnabled;
    elChkDualStack.checked = p.dualStackEnabled;
    elChkWanDrop.checked = p.simulateWanDrop;

    document.querySelectorAll('.btn-preset').forEach(b => b.classList.remove('active'));
    const btn = document.getElementById(`btn-preset-${presetKey}`);
    if (btn) btn.classList.add('active');

    updateAll();
  }

  function updateAll() {
    const cfg = getFormConfig();

    // 1. Virtual MAC
    const vmacObj = VRRPProtocolEngine.computeVMAC(cfg.vrid, cfg.version, false);
    elBadgeVmac.textContent = vmacObj.vmac;
    elBadgeVmac.title = vmacObj.description;

    // 2. Timer Calculation
    const timers = VRRPProtocolEngine.calculateTimers({
      priority: cfg.masterPriority,
      adverIntervalMs: cfg.adverIntervalMs
    });
    elValAdverTime.textContent = `${timers.adverIntervalMs} ms`;
    elValSkewTime.textContent = `${timers.skewTimeMs} ms`;
    elValMasterDown.textContent = `${timers.masterDownIntervalMs} ms`;
    elValFailoverWindow.textContent = timers.failoverDetectionTime;

    // 3. Upstream Failover Simulator
    const sim = VRRPProtocolEngine.simulateTrackingFailover({
      masterPriority: cfg.masterPriority,
      backupPriority: cfg.backupPriority,
      trackDecrement: cfg.trackDecrement,
      upstreamWanFailed: cfg.simulateWanDrop,
      preempt: cfg.preempt
    });

    elActiveNode.value = sim.activeMaster;
    if (sim.failoverTriggered) {
      elFailoverStatus.textContent = 'FAILOVER ACTIVE';
      elFailoverStatus.className = 'badge badge-amber';
      elActiveNode.style.color = 'var(--accent-amber)';
    } else if (cfg.simulateWanDrop && !sim.failoverTriggered) {
      elFailoverStatus.textContent = 'BLACKHOLE HAZARD';
      elFailoverStatus.className = 'badge badge-rose';
      elActiveNode.style.color = 'var(--accent-rose)';
    } else {
      elFailoverStatus.textContent = 'HEALTHY';
      elFailoverStatus.className = 'badge badge-green';
      elActiveNode.style.color = 'var(--accent-green)';
    }
    elTrackingExplanation.textContent = sim.explanation;

    // 4. 10-Point Audit
    const audit = VRRPSecurityAuditor.auditVRRPArchitecture(cfg);
    elScoreGrade.textContent = audit.grade;
    elScoreTitle.textContent = `${audit.totalScore} / ${audit.maxScore} Points (${audit.passed ? 'Passed' : 'Failed'})`;
    elScoreSummary.textContent = audit.summary;
    elScoreBanner.className = `score-badge-large ${audit.passed ? 'grade-A' : 'grade-F'}`;

    elFindingsContainer.innerHTML = '';
    audit.findings.forEach(f => {
      const item = document.createElement('div');
      item.className = `finding-item ${f.status.toLowerCase()}`;
      item.innerHTML = `
        <div class="finding-title">
          <span>${f.name}</span>
          <span style="font-family: var(--font-mono);">${f.score}/${f.maxScore} pts</span>
        </div>
        <div class="finding-desc">${f.description}</div>
        ${f.remediation ? `<div class="finding-remediation">Remediation: ${f.remediation}</div>` : ''}
      `;
      elFindingsContainer.appendChild(item);
    });

    // 5. Binary Hex Packet Dissector
    const adverCentis = Math.round(cfg.adverIntervalMs / 10);
    const pktBytes = VRRPProtocolEngine.encodeVRRPPacket({
      version: cfg.version,
      vrid: cfg.vrid,
      priority: cfg.masterPriority,
      vip: cfg.vip,
      primaryIp: cfg.primaryIp,
      adverCentiseconds: adverCentis,
      adverSeconds: Math.max(1, Math.round(cfg.adverIntervalMs / 1000))
    });

    elBadgePacketProto.textContent = `VRRPv${cfg.version} Adver`;
    elPacketHexDump.textContent = VRRPProtocolEngine.formatHexDump(pktBytes);

    // 6. Multi-Vendor Synthesizer
    renderSynthesizer(cfg);
  }

  function renderSynthesizer(cfg) {
    let code = '';
    if (activeTab === 'cisco') {
      code = VRRPConfigSynthesizer.generateCisco(cfg);
    } else if (activeTab === 'arista') {
      code = VRRPConfigSynthesizer.generateArista(cfg);
    } else if (activeTab === 'junos') {
      code = VRRPConfigSynthesizer.generateJunos(cfg);
    } else if (activeTab === 'keepalived') {
      code = VRRPConfigSynthesizer.generateKeepalived(cfg);
    } else if (activeTab === 'prom') {
      code = VRRPConfigSynthesizer.generatePrometheus(cfg);
    }
    elSynthOutput.textContent = code;
  }

  // Event Listeners
  document.getElementById('btn-preset-enterprise').addEventListener('click', () => applyPreset('enterprise'));
  document.getElementById('btn-preset-k8s').addEventListener('click', () => applyPreset('k8s'));
  document.getElementById('btn-preset-fragile').addEventListener('click', () => applyPreset('fragile'));
  document.getElementById('btn-recalculate').addEventListener('click', updateAll);

  [elVrid, elVersion, elVip, elPrimaryIp, elMasterPriority, elBackupPriority, elAdverMs, elVlan,
   elChkTracking, elTrackDecrement, elWanIface, elChkPreempt, elPreemptDelay, elChkBfd,
   elChkTimersMatched, elChkL2Sec, elChkCopp, elChkDualStack, elChkWanDrop
  ].forEach(input => {
    input.addEventListener('change', updateAll);
  });

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      e.target.classList.add('active');
      activeTab = e.target.getAttribute('data-tab');
      renderSynthesizer(getFormConfig());
    });
  });

  elBtnCopy.addEventListener('click', () => {
    navigator.clipboard.writeText(elSynthOutput.textContent).then(() => {
      elBtnCopy.textContent = 'Copied!';
      setTimeout(() => { elBtnCopy.textContent = 'Copy Config'; }, 2000);
    });
  });

  // Initialize
  applyPreset('enterprise');
})();
