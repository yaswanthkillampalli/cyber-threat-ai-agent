// src/charts/SimpleBarChart.jsx

import { BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, CartesianGrid } from 'recharts';

const defaultData = [
  { name: 'SQL Injection', count: 400 },
  { name: 'DDoS', count: 300 },
  { name: 'Bruteforce', count: 200 },
  { name: 'Bot', count: 278 },
  { name: 'Infiltration', count: 189 },
  { name: 'Normal', count: 239 },
];

export default function SimpleBarChart({ data }) {
  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={data} layout="vertical" margin={{ left: 20 }}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis type="number" />
        <YAxis dataKey="name" type="category" width={100} />
        <Tooltip wrapperStyle={{ backgroundColor: '#333', border: 'none' }} />
        <Legend />
        <Bar dataKey="count" fill="#3b82f6" name="Attack Count" />
      </BarChart>
    </ResponsiveContainer>
  );
}
