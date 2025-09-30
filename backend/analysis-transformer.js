const COMMON_PORTS = {
  80: 'HTTP', 443: 'HTTPS', 21: 'FTP', 22: 'SSH',
  25: 'SMTP', 53: 'DNS', 3389: 'RDP',
};

function transformPredictionData(rows) {
  if (!rows || rows.length === 0) {
    return { dashboardData: {}, trafficData: {}, behaviourData: {}, packetData: {}, rawData: [] };
  }
  const getPrediction = (row) => (row.prediction || row.original_prediction || "unknown").toLowerCase();
  // Helper to get value from snake_case or PascalCase keys
  const getKey = (row, key_snake, key_pascal) => row[key_snake] ?? row[key_pascal];

  // --- 1. Filter and Categorize All Rows ---
  // We now exclusively use the 'prediction' key for all logic.
  const maliciousRows = rows.filter(r => 
        getPrediction(r) !== 'benign' && getPrediction(r) !== 'error' && getPrediction(r) !== 'rule_override_blocked'
    );
  const benignRows = rows.filter(r => getPrediction(r) === 'benign');

  // --- 2. Calculate Dashboard Data ---
  const threatLevel = Math.round((maliciousRows.length / rows.length) * 100);

  const threatBreakdown = maliciousRows.reduce((acc, row) => {
    const prediction = row.prediction || 'Unknown Attack';
    acc[prediction] = (acc[prediction] || 0) + 1;
    return acc;
  }, {});

  const topAttackedPorts = maliciousRows.reduce((acc, row) => {
    const port = getKey(row, 'dst_port', 'Dst Port');
    if (port) acc[port] = (acc[port] || 0) + 1;
    return acc;
  }, {});

  // --- 3. Calculate Traffic Data ---
  const protocolBreakdown = rows.reduce((acc, row) => {
    const protoNum = getKey(row, 'protocol', 'Protocol');
    const proto = protoNum === 6 ? 'TCP' : (protoNum === 17 ? 'UDP' : 'Other');
    acc[proto] = (acc[proto] || 0) + 1;
    return acc;
  }, {});

  // --- 4. Calculate Behaviour Data ---
  const sampleSize = 50;
  const behaviourData = {
    flowDuration: {
      benign: benignRows.slice(0, sampleSize).map(r => ({
        duration: getKey(r, 'flow_duration', 'Flow Duration'), 
        packets: (getKey(r, 'tot_fwd_pkts', 'Tot Fwd Pkts') || 0) + (getKey(r, 'tot_bwd_pkts', 'Tot Bwd Pkts') || 0)
      })),
      malicious: maliciousRows.slice(0, sampleSize).map(r => ({
        duration: getKey(r, 'flow_duration', 'Flow Duration'),
        packets: (getKey(r, 'tot_fwd_pkts', 'Tot Fwd Pkts') || 0) + (getKey(r, 'tot_bwd_pkts', 'Tot Bwd Pkts') || 0)
      })),
    },
    packetTiming: {
      benign: benignRows.slice(0, sampleSize).map(r => ({ 
        iatMean: getKey(r, 'flow_iat_mean', 'Flow IAT Mean'), 
        iatStd: getKey(r, 'flow_iat_std', 'Flow IAT Std') 
      })),
      malicious: maliciousRows.slice(0, sampleSize).map(r => ({ 
        iatMean: getKey(r, 'flow_iat_mean', 'Flow IAT Mean'), 
        iatStd: getKey(r, 'flow_iat_std', 'Flow IAT Std') 
      })),
    }
  };

  // --- 5. Calculate ALL Packet Flags Profile ---
  const flagProfiles = { SYN: {benign: 0, malicious: 0}, ACK: {benign: 0, malicious: 0}, FIN: {benign: 0, malicious: 0}, RST: {benign: 0, malicious: 0}, PSH: {benign: 0, malicious: 0}, URG: {benign: 0, malicious: 0} };

  benignRows.forEach(r => {
    flagProfiles.SYN.benign += getKey(r, 'syn_flag_cnt', 'SYN Flag Cnt') || 0;
    flagProfiles.ACK.benign += getKey(r, 'ack_flag_cnt', 'ACK Flag Cnt') || 0;
    flagProfiles.FIN.benign += getKey(r, 'fin_flag_cnt', 'FIN Flag Cnt') || 0;
    flagProfiles.RST.benign += getKey(r, 'rst_flag_cnt', 'RST Flag Cnt') || 0;
    flagProfiles.PSH.benign += getKey(r, 'psh_flag_cnt', 'PSH Flag Cnt') || 0;
    flagProfiles.URG.benign += getKey(r, 'urg_flag_cnt', 'URG Flag Cnt') || 0;
  });

  maliciousRows.forEach(r => {
    flagProfiles.SYN.malicious += getKey(r, 'syn_flag_cnt', 'SYN Flag Cnt') || 0;
    flagProfiles.ACK.malicious += getKey(r, 'ack_flag_cnt', 'ACK Flag Cnt') || 0;
    flagProfiles.FIN.malicious += getKey(r, 'fin_flag_cnt', 'FIN Flag Cnt') || 0;
    flagProfiles.RST.malicious += getKey(r, 'rst_flag_cnt', 'RST Flag Cnt') || 0;
    flagProfiles.PSH.malicious += getKey(r, 'psh_flag_cnt', 'PSH Flag Cnt') || 0;
    flagProfiles.URG.malicious += getKey(r, 'urg_flag_cnt', 'URG Flag Cnt') || 0;
  });

  // --- 6. Transformations for Recharts data (Internal Helper Functions) ---

  function transformToTrafficVolume(rawData) {
    const timeMap = {};
    rawData.forEach(item => {
      const date = new Date(item.timestamp || item.created_at);
      const hour = date.getHours().toString().padStart(2, "0");
      const timeStr = `${hour}:00`;
      const volumeBytes = (item.totlen_fwd_pkts || 0) + (item.totlen_bwd_pkts || 0);
      const volumeMB = volumeBytes / (1024 * 1024);
      timeMap[timeStr] = (timeMap[timeStr] || 0) + volumeMB;
    });
    return Object.keys(timeMap).sort().map(time => ({
      time,
      volume: parseFloat(timeMap[time].toFixed(2)),
    }));
  }

  function transformToSentReceived(rawData) {
    const labelMap = {};
    rawData.forEach(item => {
      const label = item.prediction || "Unknown"; // Use .prediction
      if (!labelMap[label]) {
        labelMap[label] = { name: label, sent: 0, received: 0 };
      }
      labelMap[label].sent += item.totlen_fwd_pkts || 0;
      labelMap[label].received += item.totlen_bwd_pkts || 0;
    });
    return Object.values(labelMap).map(item => ({
      name: item.name,
      sent: parseFloat((item.sent / (1024 * 1024 * 1024)).toFixed(3)),
      received: parseFloat((item.received / (1024 * 1024 * 1024)).toFixed(3)),
    }));
  }

  function transformToAvgPacketSize(rawData) {
    const typeMap = {};
    rawData.forEach(item => {
      const label = item.prediction || "Unknown"; // Use .prediction
      if (!typeMap[label]) {
        typeMap[label] = { name: label, total: 0, count: 0 };
      }
      typeMap[label].total += item.pkt_size_avg || 0;
      typeMap[label].count += 1;
    });
    return Object.values(typeMap).map(item => ({
      name: item.name,
      count: parseFloat((item.total / item.count).toFixed(2)),
    }));
  }

  function transformToThreatsOverTime(maliciousData) {
    if (maliciousData.length < 2) {
      return [{ time: new Date().toLocaleTimeString(), threats: maliciousData.length }];
    }
    const dateRange = maliciousData.reduce((acc, row) => {
      const currentDate = new Date(row.created_at);
      if (currentDate < acc.min) acc.min = currentDate;
      if (currentDate > acc.max) acc.max = currentDate;
      return acc;
    }, { min: new Date(maliciousData[0].created_at), max: new Date(maliciousData[0].created_at) });

    const { min: minDate, max: maxDate } = dateRange;
    const totalDuration = maxDate.getTime() - minDate.getTime();
    
    if (totalDuration === 0) {
        return [{ time: minDate.toLocaleTimeString(), threats: maliciousData.length }];
    }
    const numIntervals = 6;
    const intervalSize = totalDuration / numIntervals;
    const intervals = [];
    for (let i = 1; i <= numIntervals; i++) {
      intervals.push({
        endTime: new Date(minDate.getTime() + i * intervalSize),
        threats: 0,
      });
    }
    maliciousData.forEach(row => {
      const rowDate = new Date(row.created_at);
      for (const interval of intervals) {
        if (rowDate <= interval.endTime) {
          interval.threats++;
          break;
        }
      }
    });
    return intervals.map(interval => ({
      time: interval.endTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      threats: interval.threats,
    }));
  }

  // --- 7. Assemble the Final Object ---
  // The structure of this returned object is the same as before.
  return {
    dashboardData: {
      threatLevel,
      threatBreakdown: Object.entries(threatBreakdown).map(([name, value]) => ({ name, value })),
      topAttackedPorts: Object.entries(topAttackedPorts)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 5)
        .map(([port, count]) => ({ name: `Port ${port} (${COMMON_PORTS[port] || 'Unknown'})`, count })),
      threatsOverTime: transformToThreatsOverTime(maliciousRows),
    },
    trafficData: {
      protocolBreakdown: Object.entries(protocolBreakdown).map(([name, value]) => ({ name, value })),
      trafficVolume: transformToTrafficVolume(rows),
      sentReceived: transformToSentReceived(rows),
      recentFlows: maliciousRows.slice(0, 5).map(r => ({
        source: getKey(r, 'src_ip', 'Src IP') || 'N/A',
        dest: getKey(r, 'dst_ip', 'Dst IP') || 'N/A',
        port: getKey(r, 'dst_port', 'Dst Port'),
        protocol: getKey(r, 'protocol', 'Protocol') === 6 ? 'TCP' : 'UDP',
        type: r.prediction, // Use .prediction
      })),
    },
    behaviourData,
    packetData: {
      flagProfiles: Object.entries(flagProfiles).map(([flag, values]) => ({ flag, ...values })),
      avgPacketSize: transformToAvgPacketSize(rows),
    },
    rawData: rows[7],
  };
}

/**
 * Transforms the array of BLOCKED flows into a simplified structure 
 * for display in the frontend.
 */
function transformBlockedData(blockedRows) {
    // Helper to get consistent data (assuming standard column names)
    const getKey = (row, key) => row[key] ?? row[key.replace(/_cnt$/, '_count')] ?? row[key.toUpperCase()];

    // 1. Summarize blocked threats
    const threatBreakdown = blockedRows.reduce((acc, row) => {
        const prediction = row.original_prediction || row.prediction || 'Unknown Block';
        acc[prediction] = (acc[prediction] || 0) + 1;
        return acc;
    }, {});

    // 2. Sample recent blocked flows for the table view
    const recentFlows = blockedRows.slice(0, 5).map(r => ({
        source: getKey(r, 'src_ip') || 'N/A',
        dest: getKey(r, 'dst_ip') || 'N/A',
        port: getKey(r, 'dst_port'),
        protocol: getKey(r, 'protocol') === 6 ? 'TCP' : 'UDP',
        // Use a consistent type for display
        type: r.prediction, 
    }));

    return {
        blockedCount: blockedRows.length,
        threatBreakdown: Object.entries(threatBreakdown).map(([name, value]) => ({ name, value })),
        recentFlows: recentFlows,
    };
}

module.exports = { transformPredictionData, transformBlockedData };