import { useState, useMemo } from 'react';
import { Container, Row, Col, Card, Alert, Button, Form } from 'react-bootstrap';
import { BounceLoader } from 'react-spinners';
import { Table } from 'react-bootstrap'; 

// --- ASSUMED CHART IMPORTS (Keep these consistent) ---
import ThreatLevelGauge from '../charts/ThreatLevelGauge';
import SimpleLineChart from '../charts/SimpleLineChart';
import SimpleAreaChart from '../charts/SimpleAreaChart';
import SimpleBarChart from '../charts/SimpleBarChart';
import StackedBarChart from '../charts/StackedBarChart';
import BreakdownPieChart from '../charts/BreakdownPieChart';
import SimpleRadarChart from '../charts/SimpleRadarChart';
import ScatterPlot from '../charts/ScatterPlot';

// --- STYLES ---
const overlayStyle = {
  position: 'fixed',
  top: 0,
  left: 0,
  right: 0,
  bottom: 0,
  backgroundColor: 'rgba(0, 0, 0, 0.7)',
  display: 'flex',
  flexDirection: 'column',
  justifyContent: 'center',
  alignItems: 'center',
  zIndex: 9999,
  color: 'white'
};

// --- NEW STYLES FOR THE BLOCK COUNTER CARD ---
const BlockCounterCardStyle = {
  backgroundColor: '#0d6efd', /* Primary blue */
  color: 'white',
  textAlign: 'center',
  padding: '1.5rem',
  height: '100%'
};

const BlockCountTextStyle = {
  fontSize: '2.5rem',
  fontWeight: 'bold',
  lineHeight: 1
};

// --- NEW STYLES FOR BLOCKED TRAFFIC TABLE ---
const BlockedTableCardStyle = {
    borderColor: '#dc3545', /* Danger red border */
    borderWidth: '2px'
};

const BlockedTableHeaderStyle = {
    backgroundColor: '#dc3545', /* Danger red background */
    color: 'white'
};

const BlockedRowStyle = {
    backgroundColor: '#f8d7da', /* Light red/pink background */
};
// --- END NEW STYLES ---


// --- COMPONENT: ReanalyzeDashboard ---
export default function ReanalyzeDashboard() {
  const [analysisId, setAnalysisId] = useState('');
  const [isIdSubmitted, setIsIdSubmitted] = useState(false);
  const [status, setStatus] = useState({ type: 'idle', message: '' }); 

  const [dashboardData, setDashboardData] = useState(null);
  const [trafficData, setTrafficData] = useState(null);
  const [behaviourData, setBehaviourData] = useState(null);
  const [packetData, setPacketData] = useState(null);
  
  const [blockedData, setBlockedData] = useState(null); // 💡 NEW STATE: For the 896 blocked flows
  
  const [flowCounts, setFlowCounts] = useState({ 
    original: 0, 
    reanalyzed: 0, 
    blocked: 0,
    blockedPercentage: 0
  });

  // --- DATA COERCERS (All safe* useMemo hooks remain here) ---
  const safeThreatBreakdown = useMemo(
    () => (dashboardData?.threatBreakdown || []).map(d => ({ ...d, value: Number(d.value) || 0 })),
    [dashboardData]
  );
  const safeTopAttackedPorts = useMemo(
    () => (dashboardData?.topAttackedPorts || []).map(d => ({ ...d, count: Number(d.count) || 0 })),
    [dashboardData]
  );
  const safeThreatsOverTime = useMemo(
    () => (dashboardData?.threatsOverTime || []).map(d => ({ ...d, threats: Number(d.threats) || 0 })),
    [dashboardData]
  );
  const safeProtocolBreakdown = useMemo(
    () => (trafficData?.protocolBreakdown || []).map(d => ({ ...d, value: Number(d.value) || 0 })),
    [trafficData]
  );
  const safeTrafficVolume = useMemo(
    () => (trafficData?.trafficVolume || []).map(d => ({ ...d, volume: Number(d.volume) || 0 })),
    [trafficData]
  );
  const safeSentReceived = useMemo(
    () => (trafficData?.sentReceived || []).map(d => ({
      ...d,
      sent: Number(d.sent) || 0,
      received: Number(d.received) || 0
    })),
    [trafficData]
  );
  const safeFlagProfiles = useMemo(
    () => (packetData?.flagProfiles || []).map(d => ({
      ...d,
      benign: Number(d.benign) || 0,
      malicious: Number(d.malicious) || 0
    })),
    [packetData]
  );
  const safeAvgPacketSize = useMemo(
    () => (packetData?.avgPacketSize || []).map(d => ({ ...d, count: Number(d.count) || 0 })),
    [packetData]
  );
  const flowDurationData = useMemo(() => ({
    benign: (behaviourData?.flowDuration?.benign || []).map(d => ({
      duration: Number(d.duration) || 0,
      packets: Number(d.packets) || 0,
      size: Number(d.size) || 0
    })),
    malicious: (behaviourData?.flowDuration?.malicious || []).map(d => ({
      duration: Number(d.duration) || 0,
      packets: Number(d.packets) || 0,
      size: Number(d.size) || 0
    }))
  }), [behaviourData]);
  const packetTimingData = useMemo(() => ({
    benign: (behaviourData?.packetTiming?.benign || []).map(d => ({
      iatMean: Number(d.iatMean) || 0,
      iatStd: Number(d.iatStd) || 0
    })),
    malicious: (behaviourData?.packetTiming?.malicious || []).map(d => ({
      iatMean: Number(d.iatMean) || 0,
      iatStd: Number(d.iatStd) || 0
    }))
  }), [behaviourData]);
  // --- END DATA COERCERS ---

  const resetAll = () => {
    setAnalysisId('');
    setIsIdSubmitted(false);
    setDashboardData(null);
    setTrafficData(null);
    setBehaviourData(null);
    setPacketData(null);
    setBlockedData(null); // Reset blocked data
    setFlowCounts({ original: 0, reanalyzed: 0, blocked: 0, blockedPercentage: 0 }); 
    setStatus({ type: 'idle', message: '' });
  };

  const handleIdSubmit = (e) => {
    e.preventDefault();
    if (analysisId.trim()) {
      setIsIdSubmitted(true);
      setStatus({ type: 'idle', message: '' });
      reanalyzeOnBackend(analysisId.trim()); 
    } else {
      setStatus({ type: 'error', message: 'Please enter a valid Analysis ID (UUID).' });
    }
  };

  const reanalyzeOnBackend = async (id) => {
    if (!id) return;

    try {
      setStatus({ type: 'loading', message: `Retrieving and re-analyzing data for ID: ${id}...` });
      
      const res = await fetch('http://localhost:8000/reanalyze/rules', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ analysis_id: id }),
      });

      if (res.status === 404) {
          throw new Error(`Data not found for ID: ${id}. Check the ID and try again.`);
      }

      if (!res.ok) {
        const errorBody = await res.json();
        throw new Error(errorBody.error || `Re-analysis failed with status: ${res.status}`);
      }
      
      const payload = await res.json();
      
      const originalCount = payload.original_flow_count || 0;
      const reanalyzedCount = payload.reanalyzed_flow_count || 0;
      const blockedCount = originalCount - reanalyzedCount;
      const blockedPercentage = originalCount > 0 ? ((blockedCount / originalCount) * 100).toFixed(1) : 0;

      setDashboardData(payload.dashboardData || null);
      setTrafficData(payload.trafficData || null);
      setBehaviourData(payload.behaviourData || null);
      setPacketData(payload.packetData || null);
      setBlockedData(payload.blockedData || null); // 💡 SETTING THE BLOCKED DATA
      
      setFlowCounts({ 
        original: originalCount, 
        reanalyzed: reanalyzedCount, 
        blocked: blockedCount,
        blockedPercentage: blockedPercentage
      });

      setStatus({ type: 'success', message: 'Re-analysis with active rules complete.' });
    } catch (e) {
      setStatus({ type: 'error', message: e.message || 'An unknown error occurred during re-analysis.' });
    }
  };

  return (
    <Container fluid className="py-4">
      {/* Loading Overlay */}
      {status.type === 'loading' && (
        <div style={overlayStyle}>
          <BounceLoader color={"#3b82f6"} loading={true} size={80} />
          <p className="mt-4 fs-5">{status.message}</p>
        </div>
      )}

      {/* Input Form */}
      {!isIdSubmitted ? (
        <Card>
          <Card.Body>
            <Card.Title>Re-Analyze Historical Data with Active Rules</Card.Title>
            <Card.Text>Enter the unique Analysis ID (UUID) of a previous run to re-assess the data against currently active defense rules.</Card.Text>
            <Form onSubmit={handleIdSubmit}>
              <Form.Group controlId="analysisIdInput">
                <Form.Label>Analysis ID (UUID)</Form.Label>
                <Form.Control
                  type="text"
                  placeholder="e.g., a1b2c3d4-e5f6-7890-1234-abcdefghijkl"
                  value={analysisId}
                  onChange={(e) => setAnalysisId(e.target.value)}
                  required
                />
              </Form.Group>
              {status.type === 'error' && (
                <Alert className="mt-3 mb-0" variant="danger">{status.message}</Alert>
              )}
              <Button variant="primary" type="submit" className="mt-3">
                Load & Analyze
              </Button>
            </Form>
          </Card.Body>
        </Card>
      ) : (
        <>
          {/* Action Card */}
          <Card className="mb-4">
            <Card.Body>
              <div className="d-flex justify-content-between align-items-center">
                <div>
                  <Card.Title className="mb-1">Analysis ID Submitted</Card.Title>
                  <p className="mb-0 text-muted" style={{ wordBreak: 'break-all' }}>{analysisId}</p>
                  <p className="mt-2 mb-0 text-warning">
                    * Results reflect the current state of the defense rules (rules active **now**).
                  </p>
                </div>
                <div className="d-flex gap-2">
                  <Button variant="outline-secondary" size="sm" onClick={resetAll}>
                    Change Analysis ID
                  </Button>
                </div>
              </div>

              {status.type === 'error' && (
                <Alert className="mt-3 mb-0" variant="danger">{status.message}</Alert>
              )}
              {status.type === 'success' && (
                <Alert className="mt-3 mb-0" variant="success">{status.message}</Alert>
              )}
            </Card.Body>
          </Card>

          {/* Dashboard Display (Visible only on success) */}
          {status.type === 'success' && dashboardData && (
            <>
              {/* --- NEW BLOCK COUNT CARD --- */}
              <Row className="mb-4">
                <Col md={12}>
                  <Card style={BlockCounterCardStyle}>
                    <Card.Body>
                      <Row>
                        <Col md={4} className="border-end border-light">
                          <Card.Title className="mb-2 text-uppercase">Total Flows Analyzed</Card.Title>
                          <p style={BlockCountTextStyle}>{flowCounts.original}</p>
                          <small className="text-white-50">From original analysis job</small>
                        </Col>
                        <Col md={4} className="border-end border-light">
                          <Card.Title className="mb-2 text-uppercase">Flows Successfully Blocked</Card.Title>
                          <p style={BlockCountTextStyle}>{flowCounts.blocked}</p>
                          <small className="text-white-50">Malicious flows filtered by rules</small>
                        </Col>
                        <Col md={4}>
                          <Card.Title className="mb-2 text-uppercase">Block Success Rate</Card.Title>
                          <p style={BlockCountTextStyle}>{flowCounts.blockedPercentage}%</p>
                          <small className="text-white-50">Of original malicious traffic blocked</small>
                        </Col>
                      </Row>
                    </Card.Body>
                  </Card>
                </Col>
              </Row>
              {/* --- END BLOCK COUNT CARD --- */}

              {/* --- BLOCKED TRAFFIC ANALYSIS --- */}
              {blockedData && blockedData.blockedCount > 0 && (
                <Row className="mb-4">
                    <Col md={12}>
                        <Card style={BlockedTableCardStyle}>
                            <Card.Body>
                                <Card.Title className="text-danger">Blocked Traffic Details ({blockedData.blockedCount} Flows)</Card.Title>
                                <Card.Text>These flows were stopped by the active rules, reducing the threat level to 0%.</Card.Text>
                                
                                <Table striped bordered hover responsive size="sm">
                                    <thead>
                                        <tr style={BlockedTableHeaderStyle}>
                                            <th>Source IP</th>
                                            <th>Destination IP</th>
                                            <th>Port</th>
                                            <th>Protocol</th>
                                            <th>Original Threat</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {blockedData.recentFlows.map((r, i) => (
                                            <tr key={i} style={BlockedRowStyle}> 
                                                <td>{r.source}</td>
                                                <td>{r.dest}</td>
                                                <td>{r.port}</td>
                                                <td>{r.protocol}</td>
                                                <td>
                                                    <span className="badge bg-danger">
                                                        {r.type.replace('Rule_Blocked_Historical', 'BLOCKED')}
                                                    </span>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </Table>
                            </Card.Body>
                        </Card>
                    </Col>
                </Row>
              )}
              {/* --- END BLOCKED TRAFFIC ANALYSIS --- */}


              {/* Dashboard */}
              <Row className="mb-4">
                <Col md={4}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Threat Level (Post-Filter)</Card.Title>
                      <ThreatLevelGauge percentage={Number(dashboardData.threatLevel) || 0} />
                    </Card.Body>
                  </Card>
                </Col>
                <Col md={8}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Threats Over Time (Post-Filter)</Card.Title>
                      <SimpleLineChart data={safeThreatsOverTime} xKey="time" yKey="threats" />
                    </Card.Body>
                  </Card>
                </Col>
              </Row>

              <Row className="mb-4">
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Threat Breakdown (Post-Filter)</Card.Title>
                      <BreakdownPieChart data={safeThreatBreakdown} nameKey="name" valueKey="value" />
                    </Card.Body>
                  </Card>
                </Col>
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Top Attacked Ports (Post-Filter)</Card.Title>
                      <SimpleBarChart data={safeTopAttackedPorts} dataKey="count" nameKey="name" />
                    </Card.Body>
                  </Card>
                </Col>
              </Row>
              
              {/* ... (Other charts remain the same) ... */}
              
              {/* Traffic Analysis */}
              <Row className="mb-4">
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Traffic Volume</Card.Title>
                      <SimpleAreaChart data={safeTrafficVolume} xKey="time" yKey="volume" />
                    </Card.Body>
                  </Card>
                </Col>
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Protocol Breakdown</Card.Title>
                      <BreakdownPieChart data={safeProtocolBreakdown} nameKey="name" valueKey="value" />
                    </Card.Body>
                  </Card>
                </Col>
              </Row>

              <Row className="mb-4">
                <Col md={12}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Sent vs Received (by class)</Card.Title>
                      <StackedBarChart
                        data={safeSentReceived}
                        xKey="name"
                        stackKeys={['sent', 'received']}
                        legend
                      />
                    </Card.Body>
                  </Card>
                </Col>
              </Row>

              {/* Behaviour Analysis */}
              <Row className="mb-4">
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Flow Duration vs Packets</Card.Title>
                      <ScatterPlot
                        data={flowDurationData}
                        xAxis={{ key: 'duration', name: 'Duration', unit: 'µs' }}
                        yAxis={{ key: 'packets', name: 'Packets', unit: '' }}
                        zAxis={{ key: 'size', name: 'Payload Size', unit: 'bytes' }}
                        series={[
                          { key: 'benign', color: '#198754', name: 'Benign' },
                          { key: 'malicious', color: '#dc3545', name: 'Malicious' }
                        ]}
                      />
                    </Card.Body>
                  </Card>
                </Col>
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Packet Timing (IAT)</Card.Title>
                      <ScatterPlot
                        data={packetTimingData}
                        xAxis={{ key: 'iatMean', name: 'Mean IAT', unit: 'time' }}
                        yAxis={{ key: 'iatStd', name: 'Std Dev of IAT', unit: 'time' }}
                        zAxis={{ key: 'iatMean', name: 'Mean IAT', unit: 'time' }}
                        series={[
                          { key: 'benign', color: '#0d6efd', name: 'Benign' },
                          { key: 'malicious', color: '#fd7e14', name: 'Malicious' }
                        ]}
                      />
                    </Card.Body>
                  </Card>
                </Col>
              </Row>

              {/* Packet Analysis */}
              <Row className="mb-4">
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>TCP Flag Profiles</Card.Title>
                      <SimpleRadarChart
                        data={safeFlagProfiles}
                        angleKey="flag"
                        radiusKeys={['benign', 'malicious']}
                      />
                    </Card.Body>
                  </Card>
                </Col>
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Average Packet Size by Class</Card.Title>
                      <SimpleBarChart data={safeAvgPacketSize} dataKey="count" nameKey="name" />
                    </Card.Body>
                  </Card>
                </Col>
              </Row>
              <Row>
                <Col md={12}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Recent Malicious Flows (Post-Filter)</Card.Title>
                      <Table striped bordered hover responsive>
                        <thead>
                          <tr>
                            <th>Source IP</th>
                            <th>Destination IP</th>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>Predicted Type</th>
                          </tr>
                        </thead>
                        <tbody>
                          {(trafficData?.recentFlows || []).map((r, i) => (
                            <tr key={i}>
                              <td>{r.source}</td>
                              <td>{r.dest}</td>
                              <td>{r.port}</td>
                              <td>{r.protocol}</td>
                              <td>
                                <span 
                                  className={`badge ${r.type.toLowerCase() === 'benign' ? 'bg-success' : 'bg-danger'}`
                                  }
                                >
                                  {r.type}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </Table>
                    </Card.Body>
                  </Card>
                </Col>
              </Row>
            </>
          )}
        </>
      )}
    </Container>
  );
}