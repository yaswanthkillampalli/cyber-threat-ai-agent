import React, { useState } from 'react';
import axios from 'axios';
import { BounceLoader } from 'react-spinners';
import 'bootstrap/dist/css/bootstrap.min.css';

// --- Configuration ---
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL; // e.g., 'http://localhost:8000'
// ---------------------

// --- Custom Hardcoded CSS Styles (Revised for a "normal" look) ---
const styles = {
    // ----------------------
    // Global/Container Styles
    // ----------------------
    container: {
        backgroundColor: '#f0f2f5', // Light grey background
        color: '#343a40',           // Dark text for general content
        minHeight: '100vh',
        padding: '30px 0',
        fontFamily: "'Inter', sans-serif", // Modern sans-serif font
    },
    header: {
        color: '#343a40', // Darker text for titles
        fontWeight: 'bold',
        marginBottom: '20px',
    },
    // ----------------------
    // Form & Input Styles
    // ----------------------
    inputGroup: {
        backgroundColor: '#fff',
        borderRadius: '8px', // Rounded corners for the input group
        boxShadow: '0 2px 4px rgba(0, 0, 0, 0.08)', // Subtle shadow
        border: '1px solid #ced4da', // Light border
    },
    input: {
        backgroundColor: '#fff',
        color: '#495057',
        border: 'none', // Remove inner border
        padding: '10px 15px',
        borderRadius: '8px 0 0 8px', // Match group rounding
    },
    searchButton: {
        backgroundColor: '#007bff', // Bootstrap primary blue
        borderColor: '#007bff',
        color: '#fff',
        fontWeight: 'bold',
        transition: 'background-color 0.3s',
        borderRadius: '0 8px 8px 0', // Match group rounding
        padding: '10px 20px',
    },
    // ----------------------
    // Table Styles
    // ----------------------
    tableContainer: {
        marginTop: '30px',
        borderRadius: '8px',
        overflow: 'hidden',
        border: '1px solid #dee2e6', // Light border
        boxShadow: '0 4px 12px rgba(0, 0, 0, 0.1)', // More pronounced shadow for cards
        backgroundColor: '#fff', // White background for the table card
    },
    table: {
        marginBottom: '0',
        color: '#495057',
        backgroundColor: '#fff',
    },
    tableHeader: {
        backgroundColor: '#e9ecef', // Light grey header background
        color: '#495057',          // Dark text for headers
        borderBottom: '1px solid #dee2e6',
    },
    tableRow: {
        backgroundColor: '#fff',
        transition: 'background-color 0.2s',
    },
    tableRowEven: { // For alternating row colors
        backgroundColor: '#f8f9fa',
    },
    // ----------------------
    // Specific Column Styles
    // ----------------------
    code: {
        backgroundColor: '#e9ecef', // Lighter background for code/IDs
        color: '#c27d00',           // A distinct but not overly bright color
        padding: '2px 6px',
        borderRadius: '4px',
        fontFamily: "'Share Tech Mono', monospace", // Keep monospace for code
    },
    rawDataPre: {
        backgroundColor: '#f8f9fa', // Lighter background for JSON data
        color: '#495057',           // Darker text for readability
        padding: '10px',
        overflowX: 'auto',
        maxHeight: '150px',
        whiteSpace: 'pre-wrap',
        borderRadius: '4px',
        border: '1px solid #e9ecef',
        fontFamily: "'Share Tech Mono', monospace", // Keep monospace for raw data
    },
    // ----------------------
    // Status/Alert Styles
    // ----------------------
    alertDanger: {
        backgroundColor: '#f8d7da', // Bootstrap alert-danger background
        color: '#721c24',           // Bootstrap alert-danger text
        borderColor: '#f5c6cb',
        borderRadius: '8px',
    },
    alertInfo: {
        backgroundColor: '#d1ecf1', // Bootstrap alert-info background
        color: '#0c5460',           // Bootstrap alert-info text
        borderColor: '#bee5eb',
        borderRadius: '8px',
    },
    // ----------------------
    // Badge Styles (Override Bootstrap defaults)
    // ----------------------
    badgeSuccess: {
        backgroundColor: '#28a745', // Bootstrap success green
        color: '#fff',
        fontWeight: 'bold',
        padding: '5px 10px',
        borderRadius: '16px', // Pill-shaped badge
    },
    badgeDanger: {
        backgroundColor: '#dc3545', // Bootstrap danger red
        color: '#fff',
        fontWeight: 'bold',
        padding: '5px 10px',
        borderRadius: '16px',
    }
};
// ------------------------------------

const DefenseRules = () => {
    const [analysisId, setAnalysisId] = useState('');
    const [rules, setRules] = useState([]);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState(null);
    const [isDataFetched, setIsDataFetched] = useState(false);

    const fetchRules = async () => {
        if (!analysisId.trim()) {
            setError('Please enter a valid Analysis ID.');
            setRules([]);
            return;
        }
        setIsLoading(true);
        setError(null);
        setRules([]);
        try {
            const response = await axios.get(`${API_BASE_URL}/api/rules/${analysisId.trim()}`);
            setRules(response.data);
        } catch (err) {
            console.error("Error fetching rules:", err);
            if (err.response) {
                if (err.response.status === 404) {
                    setError(`No rules found for Analysis ID: ${analysisId.trim()}`);
                } else {
                    setError(`Server Error (${err.response.status}): ${err.response.data.error || 'Failed to fetch rules.'}`);
                }
            } else if (err.request) {
                setError('Network Error: Could not reach the API server.');
            } else {
                setError('An unexpected error occurred while setting up the request.');
            }
            setRules([]);
        } finally {
            setIsLoading(false);
            setIsDataFetched(true);
        }
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        fetchRules();
    };

    // --- Render Content ---
    const renderContent = () => {
        if (isLoading) {
            return (
                <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '200px' }}>
                    <BounceLoader color={"#007bff"} loading={isLoading} size={60} />
                </div>
            );
        }

        if (error) {
            return (
                <div className="alert mt-3" style={styles.alertDanger} role="alert">
                    {error}
                </div>
            );
        }

        if (isDataFetched && rules.length === 0) {
            return (
                <div className="alert mt-3" style={styles.alertInfo} role="alert">
                    No defense rules found for Analysis ID: <code style={styles.code}>{analysisId.trim()}</code>
                </div>
            );
        }

        if (rules.length > 0) {
            return (
                <div style={styles.tableContainer}>
                    <h5 className="p-3" style={{ ...styles.header, fontSize: '1.25rem', marginBottom: 0, backgroundColor: styles.tableHeader.backgroundColor, borderRadius: '8px 8px 0 0' }}>
                        Found {rules.length} Rules for Analysis ID: <code style={styles.code}>{analysisId.trim()}</code>
                    </h5>
                    <div className="table-responsive">
                        <table className="table table-hover" style={styles.table}>
                            <thead style={styles.tableHeader}>
                                <tr>
                                    <th style={styles.tableHeader}>Rule ID</th>
                                    <th style={styles.tableHeader}>IP Address</th>
                                    <th style={styles.tableHeader}>Threat Type</th>
                                    <th style={styles.tableHeader}>Active</th>
                                    <th style={styles.tableHeader}>Created At</th>
                                    <th style={styles.tableHeader}>Raw Data</th>
                                </tr>
                            </thead>
                            <tbody>
                                {rules.map((rule, index) => (
                                    <tr key={rule.id} style={index % 2 === 0 ? styles.tableRow : styles.tableRowEven}>
                                        <td style={{ verticalAlign: 'middle' }} className="text-monospace small"><code style={styles.code}>{rule.id}</code></td>
                                        <td style={{ verticalAlign: 'middle' }}>{rule.ip_address}</td>
                                        <td style={{ verticalAlign: 'middle' }}>{rule.threat_type}</td>
                                        <td style={{ verticalAlign: 'middle' }}>
                                            <span style={rule.is_active ? styles.badgeSuccess : styles.badgeDanger}>
                                                {rule.is_active ? 'ACTIVE' : 'INACTIVE'}
                                            </span>
                                        </td>
                                        <td style={{ verticalAlign: 'middle' }} className="small">{new Date(rule.created_at).toLocaleString()}</td>
                                        <td>
                                            <pre style={styles.rawDataPre} className="mb-0 small">{JSON.stringify(rule.raw_flow_data, null, 2)}</pre>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            );
        }

        return (
            <div className="alert mt-3" style={styles.alertInfo} role="alert">
                Ready to retrieve defense rules. Enter a unique Analysis ID and click Search.
            </div>
        );
    };

    return (
        <div style={styles.container}>
            <div className="container">
                <h1 style={styles.header}>Defense Rule Lookup</h1>
                <p className="lead" style={{ color: '#6c757d' }}> {/* Lighter grey for lead text */}
                    Query the backend for rules created under a specific **Analysis ID**.
                </p>
                <form onSubmit={handleSubmit} className="mb-5">
                    <div className="input-group">
                        <input
                            type="text"
                            className="form-control"
                            placeholder="e.g., 9667feab-6e86-4e44-9d55-b581ba87396b"
                            value={analysisId}
                            onChange={(e) => setAnalysisId(e.target.value)}
                            disabled={isLoading}
                            style={styles.input}
                        />
                        <button
                            className="btn"
                            type="submit"
                            disabled={isLoading}
                            style={styles.searchButton}
                        >
                            {isLoading ? 'Searching...' : 'Search Rules'}
                        </button>
                    </div>
                    <div className="form-text mt-2" style={{ color: '#6c757d' }}>
                        **Note:** Use the ID: <code style={styles.code}>9667feab-6e86-4e44-9d55-b581ba87396b</code> to test.
                    </div>
                </form>
                {renderContent()}
            </div>
        </div>
    );
};

export default DefenseRules;