// src/charts/SimpleRadarChart.jsx

import { Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer, Legend, Tooltip } from 'recharts';

export default function SimpleRadarChart({ data }) {
  return (
    <ResponsiveContainer width="100%" height={300}>
      <RadarChart cx="50%" cy="50%" outerRadius="80%" data={data}>
        <PolarGrid />
        <PolarAngleAxis dataKey="flag" />
        <PolarRadiusAxis angle={30} domain={[0, 'dataMax + 10']} />
        <Tooltip />
        <Legend />
        <Radar name="Benign Traffic" dataKey="benign" stroke="#22c55e" fill="#22c55e" fillOpacity={0.6} />
        <Radar name="Malicious Traffic" dataKey="malicious" stroke="#ef4444" fill="#ef4444" fillOpacity={0.6} />
      </RadarChart>
    </ResponsiveContainer>
  );
}