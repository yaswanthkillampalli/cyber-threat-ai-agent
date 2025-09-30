import { useState, useCallback, useMemo, useEffect } from 'react'; 
import { useDropzone } from 'react-dropzone'; // Correctly imported
import { Container, Row, Col, Card, Table, Alert, Button } from 'react-bootstrap';

// Reusable charts (assumed existing)
import { BounceLoader } from 'react-spinners';
import ThreatLevelGauge from '../charts/ThreatLevelGauge';
import SimpleLineChart from '../charts/SimpleLineChart';
import SimpleAreaChart from '../charts/SimpleAreaChart';
import SimpleBarChart from '../charts/SimpleBarChart';
import StackedBarChart from '../charts/StackedBarChart';
import BreakdownPieChart from '../charts/BreakdownPieChart';
import SimpleRadarChart from '../charts/SimpleRadarChart';
import ScatterPlot from '../charts/ScatterPlot';

// --- STYLES ---

// Dropzone styles
const baseStyle = {
  flex: 1,
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
  padding: '40px',
  border: '2px dashed #007bff',
  borderRadius: '0.375rem',
  backgroundColor: '#f8f9fa',
  color: '#6c757d',
  transition: 'border .24s ease-in-out',
  cursor: 'pointer'
};
const activeStyle = {
  borderColor: '#0b5ed7'
};

// Style for the full-screen loading overlay
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

// ⭐ HARDCODED CSS FOR THE CUSTOM NOTIFICATION
const notificationStyle = {
  container: {
    position: 'fixed',
    top: '20px',
    right: '20px',
    backgroundColor: '#e6f7ff', 
    color: '#0056b3',          
    padding: '10px 15px',
    borderRadius: '5px',
    boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
    zIndex: 10000,
    minWidth: '200px',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
    transition: 'opacity 0.3s ease-in-out',
    opacity: 1
  },
  content: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center'
  },
  closeButton: {
    background: 'none',
    border: 'none',
    color: '#0056b3',
    cursor: 'pointer',
    fontSize: '1rem',
    fontWeight: 'bold',
    marginLeft: '10px'
  },
  progressBar: {
    height: '4px',
    backgroundColor: '#007bff', 
    width: '100%',
    marginTop: '5px',
    transition: 'width 1.5s linear' 
  }
};

// ⭐ HARDCODED CSS FOR THE ANALYSIS ID CONTAINER
const analysisIdContainerStyle = {
  marginTop: '1rem',
  padding: '10px',
  backgroundColor: '#f8f9fa',
  border: '1px solid #ced4da',
  borderRadius: '4px',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between'
};

const analysisIdCodeStyle = {
  fontSize: '0.9rem',
  fontFamily: 'monospace',
  color: '#495057',
  backgroundColor: '#e9ecef',
  padding: '2px 6px',
  borderRadius: '3px',
  overflowX: 'auto',
  whiteSpace: 'nowrap',
  wordBreak: 'break-all',
  flexGrow: 1,
  marginRight: '10px'
};

// ⭐ COPIED NOTIFICATION COMPONENT
const CopiedNotification = ({ isVisible, onClose }) => {
  const [width, setWidth] = useState(100);

  useEffect(() => {
    if (isVisible) {
      setWidth(100);
      const resetTimer = setTimeout(() => {
          setWidth(0);
      }, 50); 
      
      const closeTimer = setTimeout(() => {
        onClose();
      }, 1500);

      return () => {
        clearTimeout(resetTimer);
        clearTimeout(closeTimer);
      };
    } else {
      setWidth(100); 
    }
  }, [isVisible, onClose]);

  if (!isVisible) return null;

  return (
    <div style={{ ...notificationStyle.container, opacity: isVisible ? 1 : 0 }}>
      <div style={notificationStyle.content}>
        <p style={{ margin: 0, fontWeight: 500 }}>Copied!</p>
        <button style={notificationStyle.closeButton} onClick={onClose}>
          &times; 
        </button>
      </div>
      <div style={{ ...notificationStyle.progressBar, width: `${width}%` }}></div>
    </div>
  );
};

const APP_BASE_URL = import.meta.env.VITE_API_BASE_URL;

export default function CSVAnalysis() {
  const [file, setFile] = useState(null);
  const [status, setStatus] = useState({ type: 'idle', message: '' }); 

  const [analysisId, setAnalysisId] = useState(null); 
  const [copied, setCopied] = useState(false); 

  // Server-returned data
  const [dashboardData, setDashboardData] = useState(null);
  const [trafficData, setTrafficData] = useState(null);
  const [behaviourData, setBehaviourData] = useState(null);
  const [packetData, setPacketData] = useState(null);

  const onDrop = useCallback((acceptedFiles) => {
    if (!acceptedFiles?.length) return;
    const uploadedFile = acceptedFiles[0];
    if (uploadedFile.type !== 'text/csv' && !uploadedFile.name?.toLowerCase().endsWith('.csv')) {
      setStatus({ type: 'error', message: 'Invalid file type. Please upload a CSV file.' });
      return;
    }
    setFile(uploadedFile);
    setStatus({ type: 'idle', message: '' });
  }, []);

  // ⭐ CRITICAL FIX: Assigning the return values from useDropzone
  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: false,
    accept: { 'text/csv': ['.csv'] }
  });
  // -------------------------------------------------------------

  // ... (useMemo hooks for data safety remain unchanged)
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

  // Scatter data adapters
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

  const resetAll = () => {
    setFile(null);
    setDashboardData(null);
    setTrafficData(null);
    setBehaviourData(null);
    setPacketData(null);
    setStatus({ type: 'idle', message: '' });
    setAnalysisId(null); 
  };

  const uploadToBackend = async () => {
    if (!file) return;
    try {
      setAnalysisId(null); 
      setStatus({ type: 'uploading', message: `Uploading and analyzing ${file.name}...` });
      
      const formData = new FormData();
      formData.append('csvfile', file);
      
      const res = await fetch( APP_BASE_URL + '/analyze/csv', {
        method: 'POST',
        body: formData
      });
      
      if (!res.ok) throw new Error(`Upload failed with status: ${res.status}`);
      
      const payload = await res.json();
      
      setAnalysisId(payload.analysis_id || null);

      setDashboardData(payload.dashboardData || null);
      setTrafficData(payload.trafficData || null);
      setBehaviourData(payload.behaviourData || null);
      setPacketData(payload.packetData || null);

      setStatus({ type: 'success', message: 'Analysis complete. ID saved.' });
    } catch (e) {
      setStatus({ type: 'error', message: e.message || 'An unknown error occurred' });
    }
  };

  const copyAnalysisId = async () => {
    if (analysisId) {
      await navigator.clipboard.writeText(analysisId);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500); 
    }
  };

  return (
    <Container fluid className="py-4">
      
      <CopiedNotification isVisible={copied} onClose={() => setCopied(false)} />

      {/* NEW: Full-screen loading overlay */}
      {status.type === 'uploading' && (
        <div style={overlayStyle}>
          <BounceLoader color={"#3b82f6"} loading={true} size={80} />
          <p className="mt-4 fs-5">{status.message}</p>
        </div>
      )}

      {!file ? (
        // The JSX now correctly uses the variables returned by useDropzone
        <div {...getRootProps({ style: isDragActive ? { ...baseStyle, ...activeStyle } : baseStyle })}>
          <input {...getInputProps()} />
          <p className="mb-0">Drag & drop a CSV file here, or click to select a file</p>
          <small>Network Traffic Data Only</small>
        </div>
      ) : (
        <>
          {/* MODIFIED: Restyled upload card */}
          <Card className="mb-4">
            <Card.Body>
              <div className="d-flex justify-content-between align-items-center">
                {/* File Info */}
                <div>
                  <Card.Title className="mb-1">File Selected</Card.Title>
                  <p className="mb-0 text-muted">{file.name}</p>
                
                  {/* ⭐ ANALYSIS ID DISPLAY BLOCK WITH CUSTOM CSS */}
                  {status.type === 'success' && analysisId && (
                    <div style={analysisIdContainerStyle}>
                        <div style={{ display: 'flex', alignItems: 'center' }}>
                            <strong className="me-2 text-primary">Analysis ID:</strong>
                            <code style={analysisIdCodeStyle}>{analysisId}</code>
                        </div>
                        <Button 
                            variant="outline-primary" 
                            size="sm" 
                            onClick={copyAnalysisId}
                        >
                            📋 Copy
                        </Button>
                    </div>
                  )}
                  {/* ⭐ END ANALYSIS ID BLOCK */}
                </div>
                {/* Action Buttons */}
                <div className="d-flex gap-2">
                  <Button variant="outline-secondary" size="sm" onClick={resetAll}>
                    Choose another file
                  </Button>
                  <Button
                    variant="primary"
                    onClick={uploadToBackend}
                    disabled={status.type === 'uploading'}
                  >
                    Analyze on Server
                  </Button>
                </div>
              </div>

              {/* Status alerts are now placed below the actions for a cleaner look */}
              {status.type === 'error' && (
                <Alert className="mt-3 mb-0" variant="danger">{status.message}</Alert>
              )}
              {status.type === 'success' && (
                <Alert className="mt-3 mb-0" variant="success">{status.message}</Alert>
              )}
            </Card.Body>
          </Card>
          
          {status.type === 'success' && dashboardData && (
            <>
              {/* Dashboard */}
              <Row className="mb-4">
                <Col md={4}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Threat Level</Card.Title>
                      <ThreatLevelGauge percentage={Number(dashboardData.threatLevel) || 0} />
                    </Card.Body>
                  </Card>
                </Col>
                <Col md={8}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Threats Over Time</Card.Title>
                      <SimpleLineChart data={safeThreatsOverTime} xKey="time" yKey="threats" />
                    </Card.Body>
                  </Card>
                </Col>
              </Row>

              <Row className="mb-4">
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Threat Breakdown</Card.Title>
                      <BreakdownPieChart data={safeThreatBreakdown} nameKey="name" valueKey="value" />
                    </Card.Body>
                  </Card>
                </Col>
                <Col md={6}>
                  <Card>
                    <Card.Body>
                      <Card.Title>Top Attacked Ports</Card.Title>
                      <SimpleBarChart data={safeTopAttackedPorts} dataKey="count" nameKey="name" />
                    </Card.Body>
                  </Card>
                </Col>
              </Row>

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
                      <Card.Title>Recent Malicious Flows</Card.Title>
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
                              <td><span className={`badge ${r.type === 'benign' ? 'bg-success' : 'bg-danger'}`}>{r.type}</span></td>
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