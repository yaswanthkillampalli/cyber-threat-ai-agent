// src/charts/ScatterPlot.jsx

import { ScatterChart, Scatter, XAxis, YAxis, ZAxis, Tooltip, Legend, ResponsiveContainer, CartesianGrid } from 'recharts';

export default function ScatterPlot({ data, xAxis, yAxis, zAxis }) {
  return (
    <ResponsiveContainer width="100%" height={300}>
      <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
        <CartesianGrid />
        <XAxis 
          type="number" 
          dataKey={xAxis.key} 
          name={xAxis.name} 
          unit={xAxis.unit} 
        />
        <YAxis 
          type="number" 
          dataKey={yAxis.key} 
          name={yAxis.name} 
          unit={yAxis.unit} 
        />
        <ZAxis 
          dataKey={zAxis.key} 
          range={[10, 500]} 
          name={zAxis.name} 
        />
        <Tooltip cursor={{ strokeDasharray: '3 3' }} />
        <Legend />
        {/* We can have multiple scatter series for different data types */}
        <Scatter name="Benign" data={data.benign} fill="#22c55e" shape="circle" />
        <Scatter name="Suspicious" data={data.suspicious} fill="#f97316" shape="triangle" />
        <Scatter name="Malicious" data={data.malicious} fill="#ef4444" shape="cross" />
      </ScatterChart>
    </ResponsiveContainer>
  );
}