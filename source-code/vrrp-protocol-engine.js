/**
 * VRRPForge Pro - Protocol Engineering Engine
 * Standards:
 * - RFC 5798: Virtual Router Redundancy Protocol (VRRP) Version 3 for IPv4 and IPv6
 * - RFC 3768: Virtual Router Redundancy Protocol (VRRP) Version 2 for IPv4
 * - RFC 7042 / RFC 2281: IANA Reserved Virtual MAC (VMAC) Allocation
 * - RFC 5880: Bidirectional Forwarding Detection (BFD)
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.VRRPProtocolEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // VRRP Constants per RFC 5798 & RFC 3768
  const VRRP_IP_PROTOCOL = 112; // Assigned by IANA for VRRP
  const VRRP_IPV4_MULTICAST = '224.0.0.18'; // Link-local multicast, TTL=255
  const VRRP_IPV6_MULTICAST = 'ff02::12';

  // Compute Virtual MAC (VMAC) address per RFC 5798 / RFC 7042
  function computeVMAC(vrid, version = 3, isIpv6 = false) {
    const id = Math.max(1, Math.min(255, parseInt(vrid, 10) || 1));
    const hexId = id.toString(16).padStart(2, '0');

    if (isIpv6) {
      // RFC 5798 Section 7.3: 00-00-5E-00-02-VRID
      return {
        vmac: `00:00:5e:00:02:${hexId}`,
        standard: 'RFC 5798 IPv6',
        description: `IPv6 Virtual Router MAC for VRID ${id}`
      };
    } else {
      // RFC 5798 Section 7.3 / RFC 3768 Section 7.3: 00-00-5E-00-01-VRID
      return {
        vmac: `00:00:5e:00:01:${hexId}`,
        standard: 'RFC 5798 / RFC 3768 IPv4',
        description: `IPv4 Virtual Router MAC for VRID ${id}`
      };
    }
  }

  // RFC 1071 Standard Internet Checksum
  function computeChecksum(bytes, length) {
    let sum = 0;
    let i = 0;
    const len = length !== undefined ? length : bytes.length;

    while (i < len - 1) {
      sum += (bytes[i] << 8) | bytes[i + 1];
      i += 2;
    }
    if (i < len) {
      sum += bytes[i] << 8;
    }

    while (sum >> 16) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (~sum) & 0xFFFF;
  }

  function ipToBytes(ipStr) {
    return ipStr.trim().split('.').map(x => parseInt(x, 10) & 0xFF);
  }

  /**
   * RFC 5798 Section 5.2.8 Checksum Calculation
   * VRRPv3 includes an IPv4 Pseudo-Header in the checksum computation:
   * [Src IP (4)] + [Dst IP (4 = 224.0.0.18)] + [Zero (1)] + [Proto (1 = 112)] + [VRRP Length (2)] + [VRRP Packet]
   */
  function computeVRRPv3Checksum(vrrpBytes, srcIp) {
    const vrrpLen = vrrpBytes.length;
    const pseudoHeader = new Uint8Array(12 + vrrpLen);

    // Source IP
    const srcBytes = ipToBytes(srcIp || '10.0.0.1');
    pseudoHeader.set(srcBytes, 0);

    // Destination IP: 224.0.0.18
    pseudoHeader.set([224, 0, 0, 18], 4);

    // Zero byte + Protocol 112
    pseudoHeader[8] = 0x00;
    pseudoHeader[9] = VRRP_IP_PROTOCOL;

    // VRRP Length (2 bytes)
    pseudoHeader[10] = (vrrpLen >> 8) & 0xFF;
    pseudoHeader[11] = vrrpLen & 0xFF;

    // VRRP packet with checksum bytes set to zero
    pseudoHeader.set(vrrpBytes, 12);
    pseudoHeader[12 + 6] = 0x00;
    pseudoHeader[12 + 7] = 0x00;

    return computeChecksum(pseudoHeader, pseudoHeader.length);
  }

  /**
   * Encode an RFC 5798 VRRPv3 or RFC 3768 VRRPv2 Advertisement Packet
   */
  function encodeVRRPPacket(params) {
    const version = params.version === 2 ? 2 : 3;
    const vrid = Math.max(1, Math.min(255, parseInt(params.vrid, 10) || 1));
    const priority = Math.max(0, Math.min(255, parseInt(params.priority, 10) || 100));
    const virtualIps = Array.isArray(params.virtualIps) ? params.virtualIps : [params.vip || '10.0.0.254'];
    const primaryIp = params.primaryIp || '10.0.0.1';

    let packet = [];

    if (version === 3) {
      // VRRPv3 (RFC 5798)
      // Byte 0: Version (4 bits = 3) | Type (4 bits = 1 Advertisement)
      packet.push((3 << 4) | 0x01);
      // Byte 1: VRID
      packet.push(vrid & 0xFF);
      // Byte 2: Priority (1-254; 255=Owner, 0=Graceful Master stop)
      packet.push(priority & 0xFF);
      // Byte 3: Count IPv4 Addresses
      packet.push(virtualIps.length & 0xFF);

      // Bytes 4-5: Rsvd (4 bits = 0) | Max Adver Int (12 bits in centiseconds e.g. 100cs = 1s)
      const adverCentiseconds = params.adverCentiseconds !== undefined ? parseInt(params.adverCentiseconds, 10) : 100;
      const rsvdAndAdver = adverCentiseconds & 0x0FFF;
      packet.push((rsvdAndAdver >> 8) & 0x0F, rsvdAndAdver & 0xFF);

      // Bytes 6-7: Checksum Placeholder
      packet.push(0x00, 0x00);

      // Bytes 8+: IPv4 Addresses
      for (const vip of virtualIps) {
        packet.push(...ipToBytes(vip));
      }

      // Compute and inject VRRPv3 pseudo-header checksum
      const uint8 = new Uint8Array(packet);
      const csum = computeVRRPv3Checksum(uint8, primaryIp);
      uint8[6] = (csum >> 8) & 0xFF;
      uint8[7] = csum & 0xFF;
      return uint8;

    } else {
      // VRRPv2 (RFC 3768)
      // Byte 0: Version (4 bits = 2) | Type (4 bits = 1 Advertisement)
      packet.push((2 << 4) | 0x01);
      // Byte 1: VRID
      packet.push(vrid & 0xFF);
      // Byte 2: Priority
      packet.push(priority & 0xFF);
      // Byte 3: Count IP Addrs
      packet.push(virtualIps.length & 0xFF);
      // Byte 4: Auth Type (0=No Auth, 1=Simple Text, 2=IP AH)
      const authType = params.authType !== undefined ? parseInt(params.authType, 10) : 0;
      packet.push(authType & 0xFF);
      // Byte 5: Adver Int (seconds)
      const adverSeconds = Math.max(1, Math.min(255, parseInt(params.adverSeconds, 10) || 1));
      packet.push(adverSeconds & 0xFF);

      // Bytes 6-7: Checksum Placeholder
      packet.push(0x00, 0x00);

      // Bytes 8+: IP Addresses
      for (const vip of virtualIps) {
        packet.push(...ipToBytes(vip));
      }

      // Authentication Data (8 bytes)
      if (authType === 1) {
        const pass = (params.authPassword || 'cisco').substr(0, 8);
        for (let i = 0; i < 8; i++) {
          packet.push(i < pass.length ? pass.charCodeAt(i) : 0x00);
        }
      } else {
        packet.push(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
      }

      // Compute and inject RFC 1071 standard checksum
      const uint8 = new Uint8Array(packet);
      const csum = computeChecksum(uint8, uint8.length);
      uint8[6] = (csum >> 8) & 0xFF;
      uint8[7] = csum & 0xFF;
      return uint8;
    }
  }

  /**
   * Dissect raw hex VRRP Advertisement packet
   */
  function dissectVRRPPacket(hexStr) {
    const cleanHex = hexStr.replace(/[^0-9a-fA-F]/g, '');
    if (cleanHex.length < 16) {
      return { valid: false, error: 'Packet hex too short for VRRP header (< 8 bytes)' };
    }

    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < cleanHex.length; i += 2) {
      bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
    }

    const version = (bytes[0] >> 4) & 0x0F;
    const type = bytes[0] & 0x0F;
    const vrid = bytes[1];
    const priority = bytes[2];
    const ipCount = bytes[3];
    const csum = (bytes[6] << 8) | bytes[7];

    let adverIntervalDesc = '';
    let authDesc = 'None';
    let vips = [];

    if (version === 3) {
      const adverCentis = ((bytes[4] & 0x0F) << 8) | bytes[5];
      adverIntervalDesc = `${adverCentis} centiseconds (${(adverCentis / 100).toFixed(2)}s)`;
      authDesc = 'Deprecated by RFC 5798 (Rely on L2/L3 security)';

      let offset = 8;
      for (let i = 0; i < ipCount && offset + 4 <= bytes.length; i++) {
        vips.push(`${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`);
        offset += 4;
      }
    } else {
      const authType = bytes[4];
      const adverSec = bytes[5];
      adverIntervalDesc = `${adverSec} second(s)`;
      authDesc = authType === 1 ? 'Simple Cleartext Password (RFC 3768 Insecure)' : (authType === 2 ? 'IP AH' : 'None (0)');

      let offset = 8;
      for (let i = 0; i < ipCount && offset + 4 <= bytes.length; i++) {
        vips.push(`${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`);
        offset += 4;
      }
    }

    const role = priority === 255 ? 'IP Address Owner (Master)' : (priority === 0 ? 'Graceful Stop' : (priority >= 100 ? 'Master Candidate' : 'Backup'));

    return {
      valid: true,
      protocol: `VRRPv${version}`,
      version,
      type: type === 1 ? 'Advertisement (1)' : `Unknown (${type})`,
      vrid,
      priority,
      role,
      ipCount,
      advertisementInterval: adverIntervalDesc,
      checksum: `0x${csum.toString(16).padStart(4, '0')}`,
      virtualIps: vips,
      authentication: authDesc,
      totalBytes: bytes.length
    };
  }

  /**
   * RFC 5798 Accurate Timer & Skew Calculations
   */
  function calculateTimers(params) {
    const priority = Math.max(1, Math.min(254, parseInt(params.priority, 10) || 100));
    // Interval in milliseconds
    const adverMs = parseInt(params.adverIntervalMs, 10) || 1000;

    // RFC 5798 Section 5.2.7:
    // Skew_Time = ((256 - Priority) * Master_Adver_Interval) / 256
    const skewTimeMs = Math.round(((256 - priority) * adverMs) / 256);

    // Master_Down_Interval = (3 * Master_Adver_Interval) + Skew_Time
    const masterDownIntervalMs = (3 * adverMs) + skewTimeMs;

    return {
      adverIntervalMs: adverMs,
      priority,
      skewTimeMs,
      skewTimeSeconds: (skewTimeMs / 1000).toFixed(3),
      masterDownIntervalMs,
      masterDownIntervalSeconds: (masterDownIntervalMs / 1000).toFixed(3),
      failoverDetectionTime: `~${(masterDownIntervalMs / 1000).toFixed(2)} seconds`
    };
  }

  /**
   * Upstream Interface Tracking & Priority Decrement Simulator
   */
  function simulateTrackingFailover(params) {
    const masterBasePriority = parseInt(params.masterPriority, 10) || 110;
    const backupPriority = parseInt(params.backupPriority, 10) || 100;
    const trackDecrement = parseInt(params.trackDecrement, 10) || 30;
    const upstreamWanFailed = !!params.upstreamWanFailed;
    const preemptEnabled = params.preempt !== false;

    const masterCurrentPriority = upstreamWanFailed ? Math.max(1, masterBasePriority - trackDecrement) : masterBasePriority;

    let activeMaster = 'Router-1 (Primary)';
    let failoverTriggered = false;
    let explanation = '';

    if (upstreamWanFailed) {
      if (masterCurrentPriority < backupPriority) {
        if (preemptEnabled) {
          activeMaster = 'Router-2 (Backup -> Elected Master)';
          failoverTriggered = true;
          explanation = `Upstream WAN failed. Master priority decremented by ${trackDecrement} from ${masterBasePriority} to ${masterCurrentPriority}. Since Backup priority (${backupPriority}) > ${masterCurrentPriority} and Preempt is active, Router-2 preempted and assumed Mastership.`;
        } else {
          activeMaster = 'Router-1 (Primary - Blackholing Traffic!)';
          failoverTriggered = false;
          explanation = `CRITICAL DEFECT: Upstream WAN failed and Master priority fell to ${masterCurrentPriority}, but Preemption is DISABLED on Router-2. Router-1 remains Master while WAN is severed, blackholing all downstream client traffic!`;
        }
      } else {
        activeMaster = 'Router-1 (Primary - Insufficient Decrement!)';
        failoverTriggered = false;
        explanation = `HAZARD: Upstream WAN failed and priority decremented to ${masterCurrentPriority}, but Backup priority is only ${backupPriority}. Decrement (${trackDecrement}) is insufficient to fall below Backup priority. Mastership never failed over!`;
      }
    } else {
      activeMaster = 'Router-1 (Primary)';
      failoverTriggered = false;
      explanation = `All upstream links healthy. Router-1 priority (${masterBasePriority}) maintains Mastership.`;
    }

    return {
      masterBasePriority,
      trackDecrement,
      masterCurrentPriority,
      backupPriority,
      upstreamWanFailed,
      preemptEnabled,
      activeMaster,
      failoverTriggered,
      explanation
    };
  }

  // Format Uint8Array to formatted Wireshark-style hex dump
  function formatHexDump(buffer) {
    const lines = [];
    for (let i = 0; i < buffer.length; i += 16) {
      const offset = i.toString(16).padStart(4, '0');
      const chunk = buffer.slice(i, i + 16);
      const hexParts = [];
      const asciiParts = [];

      for (let j = 0; j < 16; j++) {
        if (j < chunk.length) {
          const byte = chunk[j];
          hexParts.push(byte.toString(16).padStart(2, '0'));
          asciiParts.push((byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.');
        } else {
          hexParts.push('  ');
          asciiParts.push(' ');
        }
        if (j === 7) hexParts.push('');
      }

      lines.push(`${offset}   ${hexParts.join(' ')}   |${asciiParts.join('')}|`);
    }
    return lines.join('\n');
  }

  return {
    VRRP_IP_PROTOCOL,
    VRRP_IPV4_MULTICAST,
    VRRP_IPV6_MULTICAST,
    computeVMAC,
    computeChecksum,
    encodeVRRPPacket,
    dissectVRRPPacket,
    calculateTimers,
    simulateTrackingFailover,
    formatHexDump
  };
}));
