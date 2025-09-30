// src/components/Dashboard.jsx

import ThreatLevelGauge from '../charts/ThreatLevelGauge';
import BreakdownPieChart from '../charts/BreakdownPieChart';
import SimpleBarChart from '../charts/SimpleBarChart';
import SimpleLineChart from '../charts/SimpleLineChart';
import { Container, Row, Col, Card } from 'react-bootstrap';


export default function Dashboard({ data }) {
  if (!data) {
    return <div>Loading dashboard data...</div>;
  }

  return (
    <Container fluid>
      <Row className="mb-4">
        <Col md={3}>
          <Card>
            <Card.Body className="d-flex flex-column align-items-center">
              <Card.Title>Overall Threat Level</Card.Title>
              <ThreatLevelGauge percentage={data.threatLevel} />
            </Card.Body>
          </Card>
        </Col>
        <Col md={9}>
          <Card>
            <Card.Body>
              <Card.Title>Threats Detected (Last 6 Hours)</Card.Title>
              <SimpleLineChart data={data.threatsOverTime} />
            </Card.Body>
          </Card>
        </Col>
      </Row>

      <Row>
        <Col md={7}>
          <Card>
            <Card.Body>
              <Card.Title>Top Attacked Services</Card.Title>
              <SimpleBarChart data={data.topAttackedPorts} />
            </Card.Body>
          </Card>
        </Col>
        <Col md={5}>
          <Card>
            <Card.Body>
              <Card.Title>Threat Type Breakdown</Card.Title>
              <BreakdownPieChart data={data.threatBreakdown} />
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
}