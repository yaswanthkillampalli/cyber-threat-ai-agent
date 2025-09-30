// src/charts/SimpleLineChart.jsx

import { LineChart, Line, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, CartesianGrid } from 'recharts';

export default function SimpleLineChart({ data = [] }) {
  return (
    <ResponsiveContainer width="100%" height={300}>
      <LineChart data={data}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="time" />
        <YAxis />
        <Tooltip contentStyle={{ backgroundColor: '#fafafaff' }} />
        <Legend />
        <Line type="monotone" dataKey="threats" stroke="#ef4444" strokeWidth={2} name="Detected Threats" />
      </LineChart>
    </ResponsiveContainer>
  );
}