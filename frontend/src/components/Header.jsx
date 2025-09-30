// src/components/Header.jsx

import Nav from 'react-bootstrap/Nav';
import Button from 'react-bootstrap/Button';
import { MdOutlineSecurity } from "react-icons/md";
import { FiDownload,FiCalendar } from "react-icons/fi"; // Import a download icon
import '../styles/Header.css';

const dashboardTabs = [
  { eventKey: "0", label: "Dashboard" },
  { eventKey: "1", label: "Traffic Analysis" },
  { eventKey: "2", label: "Behavior Analysis" },
  { eventKey: "3", label: "Packet Analysis" },
  { eventKey: "4", label: "CSV Analysis" },
  { eventKey: "5", label: "Api Analysis" },
  { eventKey: "6", label: "Reanalyze" }
];

export default function Header({ selectedTab, onChange, onDateRangeClick, reportDateRange}) {
  // For now, the date range is just the current date.
  // This can be updated later with state from a date picker.
  const reportDate = new Date().toLocaleDateString('en-IN', {
    day: '2-digit', month: 'short', year: 'numeric'
  });

  const handleExport = () => {
    alert('Report export functionality will be implemented here!');
  };

  return (
    <header className="bg-dark text-white p-3 pb-0">
      {/* Top section of the header */}
      <div className='d-flex justify-content-between align-items-center mb-3'>
        {/* Left side: Title and Icon */}
        <div className='d-flex align-items-center gap-2'>
          <MdOutlineSecurity size={40} color='white'/>
          <h1 style={{ fontSize: "1.8rem", margin: 0 }}>
            Cyber Threat Prediction
          </h1>
        </div>

        {/* Right side: Report Info and Export Button */}
        <div className='d-flex align-items-center gap-3'>
          <div className='report-date-range clickable' onClick={onDateRangeClick}>
            <FiCalendar className="me-2"/>
            <span>Report for:</span> {reportDateRange}
          </div>
          <Button variant="success" onClick={handleExport} className="d-flex align-items-center gap-2">
            <FiDownload />
            Export
          </Button>
        </div>
      </div>
      
      {/* Bottom section: Navigation */}
      <Nav
        className="custom-nav" 
        activeKey={selectedTab}
        onSelect={(k) => onChange(k)}
      >
        {dashboardTabs.map((tab) => (
          <Nav.Item key={tab.eventKey}>
            <Nav.Link eventKey={tab.eventKey}>
              {tab.label}
            </Nav.Link>
          </Nav.Item>
        ))}
      </Nav>
    </header>
  );
}