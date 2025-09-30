
import { RadialBarChart, RadialBar, ResponsiveContainer, PolarAngleAxis } from 'recharts';

// Define gradient colors
const gradientColors = {
  safe: { start: '#22c55e', end: '#86efac' },
  warning: { start: '#f59e0b', end: '#fcd34d' },
  danger: { start: '#ef4444', end: '#fca5a5' },
};

// Function to determine color based on percentage
const getGradient = (percent) => {
  if (percent < 40) return gradientColors.safe;
  if (percent < 70) return gradientColors.warning;
  return gradientColors.danger;
};

export default function ThreatLevelGauge({ percentage = 0, label = "Threat Level" }) {
  const gradient = getGradient(percentage);
  const data = [{ value: percentage, name: label }];

  return (
    <ResponsiveContainer width="100%" height={300}>
      <RadialBarChart
        cx="50%"
        cy="50%"
        innerRadius="70%"
        outerRadius="100%"
        barSize={15}
        data={data}
        startAngle={90}
        endAngle={-270}
      >
        <defs>
          <linearGradient id="gaugeGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={gradient.start} />
            <stop offset="100%" stopColor={gradient.end} />
          </linearGradient>
        </defs>

        <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
        <RadialBar
          background={{ fill: '#e5e7eb' }}
          dataKey="value"
          cornerRadius={10}
          fill="url(#gaugeGradient)"
        />
        <text
          x="50%"
          y="50%"
          textAnchor="middle"
          dominantBaseline="middle"
          style={{ fontSize: '36px', fontWeight: 'bold', fill: '#374151' }}
        >
          {`${percentage}%`}
        </text>
        <text
          x="50%"
          y="65%"
          textAnchor="middle"
          dominantBaseline="middle"
          style={{ fontSize: '18px', fill: '#6b7280' }}
        >
          {label}
        </text>
      </RadialBarChart>
    </ResponsiveContainer>
  );
}
