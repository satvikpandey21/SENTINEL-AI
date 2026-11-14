import { render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { DistributionChart, RequestChart, RiskHistory } from './Charts';
import { analytics, assessment } from '../tests/fixtures';
vi.mock('react-chartjs-2', () => ({
  Line: ({ data }: { data: unknown }) => (
    <output data-testid="line-data">{JSON.stringify(data)}</output>
  ),
  Bar: ({ data }: { data: unknown }) => (
    <output data-testid="bar-data">{JSON.stringify(data)}</output>
  ),
  Doughnut: ({ data }: { data: unknown }) => (
    <output data-testid="doughnut-data">{JSON.stringify(data)}</output>
  ),
}));
describe('chart evidence and accessible tabular alternatives', () => {
  it('fills missing UTC request buckets with zero and keeps the exclusive end', () => {
    render(
      <RequestChart
        data={{
          ...analytics,
          start: '2026-11-14T00:00:00Z',
          end: '2026-11-14T03:00:00Z',
          requests_over_time: [{ timestamp: '2026-11-14T01:00:00Z', count: 2 }],
        }}
      />,
    );
    expect(JSON.parse(screen.getByTestId('line-data').textContent!).datasets[0].data).toEqual([
      0, 2, 0,
    ]);
    expect(screen.getByText('View chart data')).toBeInTheDocument();
  });
  it('renders real distribution labels and counts', () => {
    render(
      <DistributionChart
        title="HTTP status"
        items={[
          { key: '200', count: 9 },
          { key: '429', count: 3 },
        ]}
      />,
    );
    const data = JSON.parse(screen.getByTestId('bar-data').textContent!);
    expect(data.labels).toEqual(['200', '429']);
    expect(data.datasets[0].data).toEqual([9, 3]);
  });
  it('provides a severity legend and total assessments', () => {
    render(
      <DistributionChart
        title="Threat severity"
        items={[
          { key: 'high', count: 4 },
          { key: 'critical', count: 1 },
        ]}
        doughnut
      />,
    );
    expect(screen.getByText('5')).toBeInTheDocument();
    expect(screen.getByText('assessments')).toBeInTheDocument();
    expect(screen.getByTestId('doughnut-data')).toBeInTheDocument();
  });
  it('labels risk history as scores and orders it chronologically', () => {
    render(
      <RiskHistory
        assessments={[
          { ...assessment, risk_score: 65, analyzed_at: '2026-11-14T02:00:00Z' },
          {
            ...assessment,
            assessment_id: 'older',
            risk_score: 20,
            analyzed_at: '2026-11-14T01:00:00Z',
          },
        ]}
      />,
    );
    expect(JSON.parse(screen.getByTestId('line-data').textContent!).datasets[0].data).toEqual([
      20, 65,
    ]);
    expect(
      within(screen.getByRole('table', { hidden: true })).getByText('Risk score'),
    ).toBeInTheDocument();
  });
  it('uses a meaningful empty state for absent observations', () => {
    render(<DistributionChart title="Empty" items={[]} />);
    expect(screen.getByText('No observations in this window')).toBeInTheDocument();
    expect(screen.queryByTestId('bar-data')).not.toBeInTheDocument();
  });
});
