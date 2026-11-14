export function validateApiBase(value: string): string {
  if (value === '/api/admin') return value;
  const url = new URL(value);
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname.replace(/\/$/, '') !== '/api/admin' ||
    (url.protocol !== 'https:' && !(import.meta.env.DEV && local && url.protocol === 'http:'))
  ) {
    throw new Error(
      'Configure a same-site HTTPS API ending in /api/admin, or use the local development proxy.',
    );
  }
  return value.replace(/\/$/, '');
}
export const API_BASE = validateApiBase(import.meta.env.VITE_API_BASE_URL || '/api/admin');
