// src/charts/SimpleAreaChart.jsx

import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';

const defaultData = [
  { time: '00:00', volume: 240 },
  { time: '04:00', volume: 139 },
  { time: '08:00', volume: 980 },
  { time: '12:00', volume: 390 },
  { time: '16:00', volume: 480 },
  { time: '20:00', volume: 380 },
  { time: '24:00', volume: 430 },
];

export default function SimpleAreaChart({ data }) {
  return (
    <ResponsiveContainer width="100%" height={300}>
      <AreaChart data={data} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="time" />
        <YAxis label={{ value: 'Megabytes (MB)', angle: -90, position: 'insideLeft' }} />
        <Tooltip wrapperStyle={{ backgroundColor: '#333', border: 'none' }} />
        <Area type="monotone" dataKey="volume" stroke="#16a34a" fill="#4ade80" name="Traffic Volume" />
      </AreaChart>
    </ResponsiveContainer>
  );
}
