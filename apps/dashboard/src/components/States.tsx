import { AlertCircle, Database, LoaderCircle, RefreshCw, Search } from 'lucide-react';
import { ApiError, errorMessage } from '../api/http';
export function LoadingState({ label = 'Loading security records' }: { label?: string }) {
  return (
    <div className="state-box" role="status">
      <LoaderCircle className="spin" size={26} />
      <strong>{label}</strong>
      <span>Retrieving data from the administrative API.</span>
    </div>
  );
}
export function EmptyState({
  title = 'No records in this window',
  description = 'Try a wider time range or adjust your filters.',
  search = false,
}: {
  title?: string;
  description?: string;
  search?: boolean;
}) {
  const Icon = search ? Search : Database;
  return (
    <div className="state-box empty">
      <span className="state-icon">
        <Icon size={26} />
      </span>
      <strong>{title}</strong>
      <span>{description}</span>
    </div>
  );
}
export function ErrorState({ error, retry }: { error: unknown; retry?: () => void }) {
  return (
    <div className="notice danger" role="alert">
      <AlertCircle size={19} />
      <div>
        <strong>{errorMessage(error)}</strong>
        {error instanceof ApiError && error.status === 429 && (
          <p>
            Rate limit reached.{' '}
            {error.retryAfter
              ? `Try again after ${error.retryAfter} seconds.`
              : 'Wait before retrying.'}
          </p>
        )}
        {error instanceof ApiError && error.issues?.length ? (
          <ul>
            {error.issues.map((issue, i) => (
              <li key={i}>
                {issue.location.join(' → ')}: {issue.type.replaceAll('_', ' ')}
              </li>
            ))}
          </ul>
        ) : null}
        {error instanceof ApiError && error.requestId && (
          <small>Reference: {error.requestId}</small>
        )}
      </div>
      {retry && (
        <button className="button small secondary" onClick={retry}>
          <RefreshCw size={14} />
          Retry
        </button>
      )}
    </div>
  );
}
