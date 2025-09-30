// src/components/LoadingOverlay.jsx

import Loader from 'react-loaders';
import 'loaders.css/src/animations/line-scale.scss'; 
import '../styles/LoadingOverlay.css';

export default function LoadingOverlay({ isLoading }) {
  if (!isLoading) {
    return null;
  }

  return (
    <div className="loading-overlay">
      <Loader type="line-scale" active={true} />
      <p>Analyzing Data...</p>
    </div>
  );
}