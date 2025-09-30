
import React, { useState } from 'react';
import { Modal, Button, Form, Row, Col, ListGroup, CloseButton } from 'react-bootstrap';

const RULE_FIELDS = [
    'dst_port', 'protocol', 'flow_duration', 'tot_fwd_pkts', 
    'tot_bwd_pkts', 'prediction', 'flow_byts_s', 'flow_pkts_s'
];
const OPERATORS = ['IS', 'IS_NOT', 'GREATER_THAN', 'LESS_THAN'];

export default function RuleBuilderModal({ show, onHide, onSubmit, isLoading }) {
    const [rules, setRules] = useState([]);
    const [currentRule, setCurrentRule] = useState({
        field: RULE_FIELDS[0],
        operator: OPERATORS[0],
        value: ''
    });

    const handleAddRule = () => {
        if (!currentRule.value.trim()) {
            alert('Please enter a value for the rule.');
            return;
        }
        setRules([...rules, currentRule]);
        // Reset for next rule
        setCurrentRule({ field: RULE_FIELDS[0], operator: OPERATORS[0], value: '' });
    };

    const handleRemoveRule = (indexToRemove) => {
        setRules(rules.filter((_, index) => index !== indexToRemove));
    };

    const handleSubmit = () => {
        if (rules.length === 0) {
            alert('Please add at least one rule before applying.');
            return;
        }
        onSubmit(rules);
    };

    return (
        <Modal show={show} onHide={onHide} size="lg" centered>
            <Modal.Header closeButton>
                <Modal.Title>Create Analysis Rules</Modal.Title>
            </Modal.Header>
            <Modal.Body>
                {/* Rule Creation Form */}
                <Form>
                    <Row className="align-items-end g-2">
                        <Col md={4}>
                            <Form.Label>Field</Form.Label>
                            <Form.Select 
                                value={currentRule.field} 
                                onChange={e => setCurrentRule({...currentRule, field: e.target.value})}>
                                {RULE_FIELDS.map(f => <option key={f} value={f}>{f}</option>)}
                            </Form.Select>
                        </Col>
                        <Col md={3}>
                            <Form.Label>Operator</Form.Label>
                            <Form.Select 
                                value={currentRule.operator}
                                onChange={e => setCurrentRule({...currentRule, operator: e.target.value})}>
                                {OPERATORS.map(op => <option key={op} value={op}>{op}</option>)}
                            </Form.Select>
                        </Col>
                        <Col md={3}>
                            <Form.Label>Value</Form.Label>
                            <Form.Control 
                                type="text" 
                                placeholder="e.g., 80 or benign"
                                value={currentRule.value}
                                onChange={e => setCurrentRule({...currentRule, value: e.target.value})}
                            />
                        </Col>
                        <Col md={2}>
                            <Button variant="outline-primary" className="w-100" onClick={handleAddRule}>Add</Button>
                        </Col>
                    </Row>
                </Form>

                <hr />

                {/* List of Added Rules */}
                <h6>Active Rules</h6>
                <ListGroup>
                    {rules.length > 0 ? (
                        rules.map((rule, index) => (
                            <ListGroup.Item key={index} className="d-flex justify-content-between align-items-center">
                                <div>
                                    <span className="fw-bold">{rule.field}</span> {rule.operator.replace('_', ' ')} <span className="text-primary">{rule.value}</span>
                                </div>
                                <CloseButton onClick={() => handleRemoveRule(index)} />
                            </ListGroup.Item>
                        ))
                    ) : (
                        <p className="text-muted">No rules added yet.</p>
                    )}
                </ListGroup>
            </Modal.Body>
            <Modal.Footer>
                <Button variant="secondary" onClick={onHide}>Cancel</Button>
                <Button variant="primary" onClick={handleSubmit} disabled={isLoading || rules.length === 0}>
                    {isLoading ? 'Applying...' : 'Apply Rules & Re-Analyze'}
                </Button>
            </Modal.Footer>
        </Modal>
    );
}