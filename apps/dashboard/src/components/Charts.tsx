import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  LineController,
  BarController,
  DoughnutController,
  Filler,
  Tooltip,
  Legend,
  type ChartOptions,
} from 'chart.js';
import { Bar, Doughnut, Line } from 'react-chartjs-2';
import type { Analytics, Assessment } from '../api/types';
import { EmptyState } from './States';
import { number, shortTime, label } from '../utils/format';
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  LineController,
  BarController,
  DoughnutController,
  Filler,
  Tooltip,
  Legend,
);
ChartJS.defaults.color = '#8e9eb7';
ChartJS.defaults.font.family = 'Inter, Segoe UI, sans-serif';
ChartJS.defaults.font.size = 11;
const colors = ['#46c9bc', '#e9b65c', '#ec8d6b', '#ef667c', '#9d91f2'];
const severityColors: Record<string, string> = {
  low: '#46c9bc',
  moderate: '#e9b65c',
  high: '#ec8d6b',
  critical: '#ef667c',
};
function ChartData({
  labels,
  values,
  valueLabel = 'Count',
}: {
  labels: string[];
  values: number[];
  valueLabel?: string;
}) {
  return (
    <details className="chart-data">
      <summary>View chart data</summary>
      <table>
        <thead>
          <tr>
            <th>Bucket</th>
            <th>{valueLabel}</th>
          </tr>
        </thead>
        <tbody>
          {labels.map((text, index) => (
            <tr key={text + index}>
              <td>{text}</td>
              <td>{number(values[index] ?? 0)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  );
}
export function RequestChart({ data }: { data: Analytics }) {
  if (!data.requests_over_time.length)
    return (
      <EmptyState
        title="No request observations"
        description="Monitored HTTP traffic will appear here after the worker persists it."
      />
    );
  const counts = new Map(
    data.requests_over_time.map((row) => [new Date(row.timestamp).getTime(), row.count]),
  );
  const step = data.bucket === 'day' ? 86400000 : 3600000;
  const start = Math.floor(new Date(data.start).getTime() / step) * step;
  const end = new Date(data.end).getTime();
  const timestamps: number[] = [];
  for (let value = start; value < end && timestamps.length < 745; value += step)
    timestamps.push(value);
  const values = timestamps.map((time) => counts.get(time) ?? 0);
  const labels = timestamps.map((time) =>
    data.bucket === 'day'
      ? new Date(time).toISOString().slice(0, 10)
      : new Date(time).toISOString().slice(0, 16) + 'Z',
  );
  const options: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    plugins: { legend: { display: false } },
    scales: {
      x: {
        grid: { display: false },
        ticks: {
          maxTicksLimit: 6,
          callback: (_value, index) => {
            const stamp = timestamps[index];
            return stamp === undefined
              ? ''
              : data.bucket === 'day'
                ? new Date(stamp).toISOString().slice(5, 10)
                : shortTime(new Date(stamp).toISOString());
          },
        },
      },
      y: {
        beginAtZero: true,
        grid: { color: 'rgba(142,158,183,.09)' },
        ticks: { precision: 0, maxTicksLimit: 5 },
      },
    },
  };
  return (
    <>
      <div className="chart-container timeline">
        <Line
          role="img"
          aria-label="Monitored requests over time"
          data={{
            labels,
            datasets: [
              {
                label: 'HTTP requests',
                data: values,
                borderColor: '#46c9bc',
                backgroundColor: 'rgba(70,201,188,.10)',
                borderWidth: 2,
                fill: true,
                tension: 0.25,
                pointRadius: values.length > 24 ? 0 : 3,
                pointHoverRadius: 5,
              },
            ],
          }}
          options={options}
        />
      </div>
      <ChartData labels={labels} values={values} />
    </>
  );
}
export function DistributionChart({
  title,
  items,
  doughnut = false,
}: {
  title: string;
  items: { key: string; count: number }[];
  doughnut?: boolean;
}) {
  if (!items.length || items.every((row) => row.count === 0))
    return (
      <EmptyState
        title="No observations in this window"
        description="This distribution will populate as relevant records arrive."
      />
    );
  const labels = items.map((row) => label(row.key));
  const values = items.map((row) => row.count);
  const palette = items.map(
    (row, index) => severityColors[row.key] ?? colors[index % colors.length] ?? '#46c9bc',
  );
  const datasets = [{ label: 'Records', data: values, backgroundColor: palette, borderWidth: 0 }];
  const options: ChartOptions<'bar'> = {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    indexAxis: 'y',
    plugins: { legend: { display: false } },
    scales: {
      x: { beginAtZero: true, grid: { color: 'rgba(142,158,183,.09)' }, ticks: { precision: 0 } },
      y: { grid: { display: false } },
    },
  };
  return (
    <>
      <div className={doughnut ? 'donut-layout' : 'chart-container distribution'}>
        {doughnut ? (
          <>
            <div className="donut-chart">
              <Doughnut
                role="img"
                aria-label={title}
                data={{ labels, datasets }}
                options={{
                  responsive: true,
                  maintainAspectRatio: false,
                  animation: false,
                  cutout: '76%',
                  plugins: { legend: { display: false } },
                }}
              />
              <div className="donut-center">
                <strong>{number(values.reduce((a, b) => a + b, 0))}</strong>
                <span>assessments</span>
              </div>
            </div>
            <ul className="chart-legend">
              {items.map((row, index) => (
                <li key={row.key}>
                  <span style={{ background: palette[index] }} />
                  <span>{label(row.key)}</span>
                  <strong>{number(row.count)}</strong>
                </li>
              ))}
            </ul>
          </>
        ) : (
          <Bar role="img" aria-label={title} data={{ labels, datasets }} options={options} />
        )}
      </div>
      <ChartData labels={labels} values={values} />
    </>
  );
}
export function RiskHistory({ assessments }: { assessments: Assessment[] }) {
  const rows = [...assessments].reverse();
  const labels = rows.map((row) => row.analyzed_at);
  const values = rows.map((row) => row.risk_score);
  const options: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    plugins: { legend: { display: false } },
    scales: {
      x: {
        grid: { display: false },
        ticks: { maxTicksLimit: 6, callback: (_value, index) => shortTime(labels[index] ?? '') },
      },
      y: { min: 0, max: 100, grid: { color: 'rgba(142,158,183,.09)' } },
    },
  };
  return (
    <>
      <div className="chart-container timeline">
        <Line
          role="img"
          aria-label="Observed client risk history"
          data={{
            labels,
            datasets: [
              {
                label: 'Assessment risk',
                data: values,
                borderColor: '#e9b65c',
                backgroundColor: 'rgba(233,182,92,.08)',
                fill: true,
                borderWidth: 2,
                pointRadius: rows.length > 20 ? 1 : 3,
                tension: 0,
              },
            ],
          }}
          options={options}
        />
      </div>
      <ChartData labels={labels} values={values} valueLabel="Risk score" />
    </>
  );
}
