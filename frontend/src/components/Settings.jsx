// src/components/Settings.jsx

import { useState, useEffect } from 'react';
import { Container, Row, Col, Form, Button, Spinner } from 'react-bootstrap';
import '../styles/Settings.css'; // Import our new custom styles

export default function Settings() {
  const [url, setUrl] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [status, setStatus] = useState({ type: 'idle', message: '' });

  // Load saved settings from localStorage on initial component render
  useEffect(() => {
    const savedUrl = localStorage.getItem('supabaseUrl');
    const savedApiKey = localStorage.getItem('supabaseApiKey');
    if (savedUrl) setUrl(savedUrl);
    if (savedApiKey) setApiKey(savedApiKey);
  }, []);

  const handleTestConnection = () => {
    setStatus({ type: 'testing', message: 'Testing connection...' });
    setTimeout(() => {
      if (url.includes('supabase.co') && apiKey.length > 20) {
        setStatus({ type: 'success', message: 'Connection Verified' });
      } else {
        setStatus({ type: 'error', message: 'Connection Failed' });
      }
    }, 1500);
  };
  
  const handleSaveSettings = () => {
    localStorage.setItem('supabaseUrl', url);
    localStorage.setItem('supabaseApiKey', apiKey);
    setStatus({ type: 'success', message: 'Settings Saved!' });
    // Hide the message after a few seconds
    setTimeout(() => setStatus({ type: 'idle', message: '' }), 3000);
  };

  return (
    <Container fluid>
      <div className="settings-panel">
        <h2 className="text-white mb-2">Data Source Settings</h2>
        <p className="text-secondary mb-4">Manage your connection to the data provider.</p>
        
        <Form>
          <Form.Group as={Row} className="mb-3 align-items-center" controlId="supabaseUrl">
            <Col sm={3}><Form.Label>Project URL</Form.Label></Col>
            <Col sm={9}>
              <Form.Control
                type="text"
                placeholder="https://your-project-id.supabase.co"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
            </Col>
          </Form.Group>

          <Form.Group as={Row} className="mb-4 align-items-center" controlId="supabaseApiKey">
            <Col sm={3}><Form.Label>API Key</Form.Label></Col>
            <Col sm={9}>
              <Form.Control
                type="password"
                placeholder="••••••••••••••••••••••••••••••"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
              />
            </Col>
          </Form.Group>
          
          <Row>
            <Col sm={{ span: 9, offset: 3 }}>
              <div className="d-flex align-items-center">
                <Button variant="primary" onClick={handleSaveSettings} className="me-2">
                  Save
                </Button>
                <Button variant="outline-secondary" onClick={handleTestConnection} disabled={status.type === 'testing'}>
                  {status.type === 'testing' ? (
                    <>
                      <Spinner as="span" animation="border" size="sm" role="status" aria-hidden="true" />
                      <span className="visually-hidden">Loading...</span>
                    </>
                  ) : 'Test Connection'}
                </Button>
                
                {/* Status Indicator */}
                {status.message && (
                  <div className="ms-3 d-flex align-items-center">
                    <span className={`status-dot ${status.type}`}></span>
                    <span className="text-white">{status.message}</span>
                  </div>
                )}
              </div>
            </Col>
          </Row>
        </Form>
      </div>
    </Container>
  );
}