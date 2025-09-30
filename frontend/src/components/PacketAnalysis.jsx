// src/components/PacketAnalysis.jsx

import SimpleRadarChart from '../charts/SimpleRadarChart';
import SimpleBarChart from '../charts/SimpleBarChart';
import { Container, Row, Col, Card } from 'react-bootstrap';

// Add a default value for the data prop: { data = {} }
export default function PacketAnalysis({ data = {} }) {
  
  // Use default empty arrays to prevent mapping errors if data is not yet loaded
  const flagProfiles = data.flagProfiles || [];
  const packetSizeStats = data.packetSizeStats || [];

  // Prepare data for the bar chart safely
  const packetSizeDataForBarChart = packetSizeStats.map(item => ({
    name: item.name,
    count: item.avgSize
  }));

  return (
    <Container fluid>
      <Row>
        <Col md={6} className="mb-4">
          <Card>
            <Card.Body>
              <Card.Title>TCP Flag Profiles</Card.Title>
              {/* This chart will now safely render with an empty array if data is loading */}
              <SimpleRadarChart data={flagProfiles} />
              <hr />
              <Card.Text as="div">
                <strong>Interpretation:</strong> This chart shows the "fingerprint" of connections.
                <ul>
                  <li><span className="text-danger">Malicious traffic</span> often has a high count of <strong>SYN</strong> or <strong>RST</strong> flags.</li>
                  <li>Normal <span className="text-success">benign traffic</span> typically shows a high ratio of <strong>ACK</strong> flags.</li>
                </ul>
              </Card.Text>
            </Card.Body>
          </Card>
        </Col>
        <Col md={6} className="mb-4">
          <Card>
            <Card.Body>
              <Card.Title>Average Packet Size by Traffic Type</Card.Title>
              {/* This chart will also render safely now */}
              <SimpleBarChart data={data.avgPacketSize} />
              <hr />
              <Card.Text as="div">
                <strong>Interpretation:</strong> Packet sizes can reveal the intent of the traffic.
                <ul>
                  <li><span className="text-danger">Scanning traffic</span> uses very small packets.</li>
                  <li><span className="text-danger">Data exfiltration</span> may use consistently large packets.</li>
                </ul>
              </Card.Text>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
}