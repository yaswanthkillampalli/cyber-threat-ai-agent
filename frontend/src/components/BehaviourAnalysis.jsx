// src/components/BehaviourAnalysis.jsx

import ScatterPlot from '../charts/ScatterPlot';
import { Container, Row, Col, Card } from 'react-bootstrap';

// Add a default value for the data prop
export default function BehaviourAnalysis({ data = {} }) {
  // Use default empty arrays to prevent errors if data is missing
  const flowDurationData = data.flowDuration || { benign: [], malicious: [], suspicious: [] };
  const packetTimingData = data.packetTiming || { benign: [], malicious: [], suspicious: [] };

  return (
    <Container fluid>
      <Row>
        <Col md={6} className="mb-4">
          <Card>
            <Card.Body>
              <Card.Title>Flow Duration vs. Packet Count</Card.Title>
              <ScatterPlot 
                data={flowDurationData}
                xAxis={{ key: 'duration', name: 'Duration', unit: 's' }}
                yAxis={{ key: 'packets', name: 'Packets', unit: '' }}
                zAxis={{ key: 'size', name: 'Payload Size', unit: 'bytes' }}
              />
              <hr />
              {/* CORRECTED: The <p> tag has been removed from around the <ul> */}
              <Card.Text as="div">
                <strong>Interpretation:</strong> This chart helps identify outliers. 
                <ul>
                  <li><span className="text-danger">Malicious scans</span> often have very short durations and few packets.</li>
                  <li><span className="text-warning">Suspicious C2 traffic</span> may have very long durations but low packet counts.</li>
                  <li>Normal <span className="text-success">benign traffic</span> (like file downloads) typically shows a correlation between duration and packet count.</li>
                </ul>
              </Card.Text>
            </Card.Body>
          </Card>
        </Col>
        <Col md={6} className="mb-4">
          <Card>
            <Card.Body>
              <Card.Title>Packet Inter-Arrival Time (IAT) Analysis</Card.Title>
               <ScatterPlot 
                data={packetTimingData}
                xAxis={{ key: 'iatMean', name: 'Mean IAT', unit: 'ms' }}
                yAxis={{ key: 'iatStd', name: 'Std Dev of IAT', unit: 'ms' }}
                zAxis={{ key: 'iatMean', name: 'Mean IAT', unit: 'ms' }}
              />
              <hr />
              {/* CORRECTED: The <p> tag has been removed from around the <ul> */}
              <Card.Text as="div">
                <strong>Interpretation:</strong> This chart visualizes the "rhythm" of a connection.
                <ul>
                  <li><span className="text-danger">Automated attacks</span> often have a very low Standard Deviation (Std) in their packet timing.</li>
                  <li>Normal <span className="text-success">human activity</span> tends to have a higher Std Dev, showing more irregular packet timing.</li>
                </ul>
              </Card.Text>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
}