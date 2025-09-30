// src/charts/StackedBarChart.jsx

import { BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, CartesianGrid } from 'recharts';

const defaultData = [
  { name: 'Jan', sent: 400, received: 240 },
  { name: 'Feb', sent: 300, received: 139 },
  { name: 'Mar', sent: 200, received: 980 },
  { name: 'Apr', sent: 278, received: 390 },
  { name: 'May', sent: 189, received: 480 },
  { name: 'Jun', sent: 239, received: 380 },
  { name: 'Jul', sent: 349, received: 430 },
];

export default function StackedBarChart({ data }) {
  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={data} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="name" />
        <YAxis label={{ value: 'Gigabytes (GB)', angle: -90, position: 'insideLeft' }} />
        <Tooltip wrapperStyle={{ backgroundColor: '#333', border: 'none' }} />
        <Legend />
        <Bar dataKey="sent" stackId="a" fill="#3b82f6" name="Data Sent" />
        <Bar dataKey="received" stackId="a" fill="#8b5cf6" name="Data Received" />
      </BarChart>
    </ResponsiveContainer>
  );
}
