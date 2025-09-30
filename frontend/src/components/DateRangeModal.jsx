import { useState, useEffect } from 'react';
import { Modal, Button, Form } from 'react-bootstrap';
import DatePicker from 'react-datepicker';
import "react-datepicker/dist/react-datepicker.css";
import { FaCalendarAlt, FaTimesCircle, FaCheckCircle } from 'react-icons/fa';
import '../styles/DateRangeModal.css';

export default function DateRangeModal({ show, onHide, onApply, minDate, maxDate }) {
  const [startDate, setStartDate] = useState(null);
  const [endDate, setEndDate] = useState(null);
  const currentDate = new Date('2025-09-10T19:49:00+05:30'); // Current date: September 10, 2025, 07:49 PM IST

  useEffect(() => {
    // Set default start and end dates to current date when modal opens
    if (show && !startDate && !endDate) {
      setStartDate(currentDate);
      setEndDate(currentDate);
    } else {
      setStartDate(minDate ?? null);
      setEndDate(maxDate ?? null);
    }
  }, [show, minDate, maxDate, currentDate, startDate, endDate]);

  const handleApplyClick = () => {
    if (startDate && endDate && startDate <= endDate) {
      onApply(startDate, endDate);
      onHide();
    } else {
      alert("Please select a valid date range.");
    }
  };

  return (
    <Modal show={show} onHide={onHide} centered backdrop="static" keyboard={false} className="date-range-modal">
      <Modal.Header className="modal-header-custom">
        <div className="header-content">
          <FaCalendarAlt className="header-icon" />
          <Modal.Title as="h2">Custom Date Range</Modal.Title>
        </div>
      </Modal.Header>
      <Modal.Body className="modal-body-custom">
        <div className="date-range-info">
          <p className="text-muted-main-primary">
            Select a date range for analysis. Available data from{' '}
            <strong>{minDate ? minDate.toLocaleDateString() : '...'}</strong> to{' '}
            <strong>{maxDate ? maxDate.toLocaleDateString() : '...'}</strong>.
          </p>
        </div>
        <div className="date-range-form">
          <Form>
            <div className="date-picker-container">
              <div className="date-picker-wrapper">
                <Form.Label className="date-label">Start Date & Time</Form.Label>
                <DatePicker
                  selected={startDate}
                  onChange={(date) => setStartDate(date)}
                  selectsStart
                  startDate={startDate}
                  endDate={endDate}
                  minDate={minDate}
                  maxDate={maxDate}
                  showTimeSelect
                  timeIntervals={15}
                  timeCaption="Time"
                  dateFormat="MMMM d, yyyy h:mm aa"
                  placeholderText="Select start date & time"
                  className="date-picker-input"
                  todayButton="Today"
                  isClearable
                />
              </div>
              <div className="date-picker-wrapper">
                <Form.Label className="date-label">End Date & Time</Form.Label>
                <DatePicker
                  selected={endDate}
                  onChange={(date) => setEndDate(date)}
                  selectsEnd
                  startDate={startDate}
                  endDate={endDate}
                  minDate={startDate || minDate}
                  maxDate={maxDate}
                  showTimeSelect
                  timeIntervals={15}
                  timeCaption="Time"
                  dateFormat="MMMM d, yyyy h:mm aa"
                  placeholderText="Select end date & time"
                  className="date-picker-input"
                  todayButton="Today"
                  isClearable
                />
              </div>
            </div>
          </Form>
        </div>
      </Modal.Body>
      <Modal.Footer className="modal-footer-custom">
        <Button variant="outline-secondary" onClick={onHide} className="cancel-btn">
          <FaTimesCircle className="btn-icon" /> Cancel
        </Button>
        <Button variant="primary" onClick={handleApplyClick} className="apply-btn">
          <FaCheckCircle className="btn-icon" /> Apply
        </Button>
      </Modal.Footer>
    </Modal>
  );
}