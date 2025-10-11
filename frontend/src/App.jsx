import { useState, useEffect } from "react";
import Header from "./components/Header";
import DateRangeModal from "./components/DateRangeModal";
import Dashboard from "./components/Dashboard";
import TrafficAnalysis from "./components/TrafficAnalysis";
import BehaviourAnalysis from "./components/BehaviourAnalysis";
import PacketAnalysis from "./components/PacketAnalysis";
import CSVAnalysis from "./components/CSVAnalysis";
import ApiAnalysis from "./components/ApiAnalysis";
import Settings from "./components/Settings";
import { BounceLoader } from "react-spinners";
import './App.css';
import ReanalyzeDashboard from "./components/ReanalyzeDashboard";

// const API_BASE_URL = 'http://10.140.251.181:8000';
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL;
console.log(API_BASE_URL);

// Define which tabs rely on the main analysisData fetch (tabs 0, 1, 2, 3)
const DATA_DEPENDENT_TABS = ["0", "1", "2", "3"];

function App() {
  const [selectedTab, setSelectedTab] = useState("0");
  const [isLoading, setIsLoading] = useState(true);
  const [analysisData, setAnalysisData] = useState(null);
  const [error, setError] = useState(null);
  
  // State for the modal
  const [showModal, setShowModal] = useState(false);
  const [reportDateRange, setReportDateRange] = useState('Last 24 Hours');
  const [minDate, setMinDate] = useState(null);
  const [maxDate, setMaxDate] = useState(null);

  // This single function now handles ALL data fetching.
  const fetchDataForRange = async (start, end) => {
    // Only show loading indicator for data-dependent tabs on initial load
    if (DATA_DEPENDENT_TABS.includes(selectedTab) || start || end) {
      setIsLoading(true);
    }
    setError(null);
    let url = `${API_BASE_URL}/reports/recent`; // Default URL for initial load
    if (start && end) {
      url = `${API_BASE_URL}/reports/custom?start=${start.toISOString()}&end=${end.toISOString()}`;
    }
    try {
      const response = await fetch(url);
      if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
      const data = await response.json();
      setAnalysisData(data);
    } catch (e) {
      console.error("Failed to fetch dashboard data:", e);
      // ⭐ Only set the error message if we are on a data-dependent tab
      if (DATA_DEPENDENT_TABS.includes(selectedTab)) {
        setError("Could not load report data. Please ensure the backend server is running.");
      }
      setAnalysisData(null);
    }
    setIsLoading(false);
  };

  // useEffect now makes only ONE call on initial load.
  useEffect(() => {
    fetchDataForRange(); 
  }, []); // Empty dependency array means this runs once on mount

  // Function to open the modal
  const handleOpenModal = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/reports/date-range`);
      const range = await response.json();
      setMinDate(new Date(range.min_date));
      setMaxDate(new Date(range.max_date));
    } catch (e) {
      console.error("Could not fetch date range", e);
    }
    setShowModal(true);
  };

  const handleApplyDateRange = (start, end) => {
    const options = { day: 'numeric', month: 'short' };
    setReportDateRange(`${start.toLocaleDateString('en-IN', options)} - ${end.toLocaleDateString('en-IN', options)}`);
    fetchDataForRange(start, end);
  };
  
  const renderTabContent = () => {
    // 1. Define the components first (independent of loading/error state)
    const tabComponents = {
      "0": <Dashboard data={analysisData?.dashboardData || {}} />,
      "1": <TrafficAnalysis data={analysisData?.trafficData || {}} />,
      "2": <BehaviourAnalysis data={analysisData?.behaviourData || {}} />,
      "3": <PacketAnalysis data={analysisData?.packetData || {}}/>,
      // ⭐ These tabs are INDEPENDENT of the main report data and should always load
      "4": <CSVAnalysis />, 
      "5": <ApiAnalysis />,
      "6": <ReanalyzeDashboard />,
      "7": <Settings /> 
    };
    
    // 2. Render the selected component
    const currentComponent = tabComponents[selectedTab];

    // 3. Conditional Checks (ONLY for data-dependent tabs)
    if (DATA_DEPENDENT_TABS.includes(selectedTab)) {
      if (error) {
        return <div className="text-center text-danger p-5">{error}</div>;
      }
      if (!analysisData || analysisData.message) {
        return <div className="text-center text-muted p-5">{analysisData?.message || "No data available for this date range."}</div>;
      }
    }

    // 4. Return the component (always returns a component for independent tabs)
    return currentComponent;
  };

  return (
    <div className="main-component-app">
      <Header 
        selectedTab={selectedTab} 
        onChange={setSelectedTab} 
        onDateRangeClick={handleOpenModal} 
        reportDateRange={reportDateRange} 
      />
      <DateRangeModal 
        show={showModal}
        onHide={() => setShowModal(false)}
        onApply={handleApplyDateRange}
        minDate={minDate}
        maxDate={maxDate}
      />
      <main className="app-main-content">
        {/* ⭐ Only show loader if we are loading AND on a data-dependent tab */}
        {isLoading && DATA_DEPENDENT_TABS.includes(selectedTab) ? (
          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
            <BounceLoader color={"#3b82f6"} loading={isLoading} size={60} />
          </div>
        ) : (
          renderTabContent()
        )}
      </main>
    </div>
  );
}

export default App;