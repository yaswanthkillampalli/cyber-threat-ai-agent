// src/components/TrafficAnalysis.jsx

import StackedBarChart from '../charts/StackedBarChart';
import SimpleAreaChart from '../charts/SimpleAreaChart';
import BreakdownPieChart from '../charts/BreakdownPieChart'; 
import { Container, Row, Col, Card, Table } from 'react-bootstrap';

export default function TrafficAnalysis({ data }) {
  if (!data) {
    return <div>Loading traffic analysis data...</div>;
  }

  return (
    <Container fluid>
      <Row className="mb-4">
        <Col md={8}>
          <Card>
            <Card.Body>
              <Card.Title>Traffic Volume (Last Hour)</Card.Title>
              <SimpleAreaChart data={data.trafficVolume} />
            </Card.Body>
          </Card>
        </Col>
        <Col md={4}>
          <Card>
            <Card.Body>
              <Card.Title>Protocol Breakdown</Card.Title>
              <BreakdownPieChart data={data.protocolBreakdown} />
            </Card.Body>
          </Card>
        </Col>
      </Row>
      <Row>
        <Col md={12}>
          <Card className="mb-4">
            <Card.Body>
              <Card.Title>Data Sent vs. Received by Traffic Type</Card.Title>
              <StackedBarChart data={data.sentReceived} />
            </Card.Body>
          </Card>
          <Card>
            <Card.Body>
              <Card.Title>Recent Suspicious Flows</Card.Title>
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
                  {data.recentFlows.map((flow, index) => (
                    <tr key={index}>
                      <td>{flow.source}</td>
                      <td>{flow.dest}</td>
                      <td>{flow.port}</td>
                      <td>{flow.protocol}</td>
                      <td><span className="badge bg-danger">{flow.type}</span></td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
}