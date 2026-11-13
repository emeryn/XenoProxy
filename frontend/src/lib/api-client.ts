/**
 * Single HTTP entry point to the XenoProxy API.
 *
 * Every mutating call carries `X-Requested-With` (checked server side against
 * CSRF) and an `Idempotency-Key` generated once per user action, so a retry after
 * a flaky network never creates a second job.
 */

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    request_id: string;
    details?: unknown;
  };
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string;
  readonly details?: unknown;

  constructor(status: number, body: ApiErrorBody | null, fallback: string) {
    super(body?.error?.message ?? fallback);
    this.name = 'ApiError';
    this.status = status;
    this.code = body?.error?.code ?? 'UNKNOWN';
    this.requestId = body?.error?.request_id ?? '-';
    this.details = body?.error?.details;
  }
}

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function newIdempotencyKey(): string {
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export interface RequestOptions {
  method?: string;
  body?: unknown;
  signal?: AbortSignal;
  idempotencyKey?: string;
  query?: Record<string, string | number | boolean | undefined | null>;
}

function buildUrl(path: string, query?: RequestOptions['query']): string {
  const url = new URL(`/api/v1${path}`, window.location.origin);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== '') {
        url.searchParams.set(key, String(value));
      }
    }
  }
  return url.pathname + url.search;
}

export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = (options.method ?? 'GET').toUpperCase();
  const headers: Record<string, string> = {
    Accept: 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
  };

  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }
  if (MUTATING.has(method)) {
    headers['Idempotency-Key'] = options.idempotencyKey ?? newIdempotencyKey();
  }

  const response = await fetch(buildUrl(path, options.query), {
    method,
    headers,
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    ...(options.signal ? { signal: options.signal } : {}),
  });

  if (response.status === 204) {
    return undefined as T;
  }

  const text = await response.text();
  const payload = text ? (JSON.parse(text) as unknown) : null;

  if (!response.ok) {
    throw new ApiError(response.status, payload as ApiErrorBody | null, response.statusText);
  }
  return payload as T;
}

/** Download an export without leaving the current page. */
export async function apiDownload(path: string, filename: string): Promise<void> {
  const response = await fetch(buildUrl(path), {
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    credentials: 'same-origin',
    cache: 'no-store',
  });
  if (!response.ok) {
    const text = await response.text();
    throw new ApiError(
      response.status,
      text ? (JSON.parse(text) as ApiErrorBody) : null,
      'The export failed.',
    );
  }
  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = objectUrl;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
}

/**
 * A multipart upload.
 *
 * It does not go through `apiRequest`: that one serialises the body as JSON and
 * sets `Content-Type`, and a multipart body must be left to the browser so it
 * can write the boundary.
 */
export async function apiUpload<T>(
  path: string,
  form: FormData,
  options: { idempotencyKey?: string } = {},
): Promise<T> {
  const response = await fetch(buildUrl(path), {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      'Idempotency-Key': options.idempotencyKey ?? newIdempotencyKey(),
    },
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
    body: form,
  });

  const text = await response.text();
  const payload = text ? (JSON.parse(text) as unknown) : null;
  if (!response.ok) {
    throw new ApiError(response.status, payload as ApiErrorBody | null, response.statusText);
  }
  return payload as T;
}

export const api = {
  get: <T>(path: string, query?: RequestOptions['query']) =>
    apiRequest<T>(path, query ? { query } : {}),
  post: <T>(path: string, body?: unknown) => apiRequest<T>(path, { method: 'POST', body }),
  put: <T>(path: string, body?: unknown) => apiRequest<T>(path, { method: 'PUT', body }),
  patch: <T>(path: string, body?: unknown) => apiRequest<T>(path, { method: 'PATCH', body }),
  delete: <T>(path: string) => apiRequest<T>(path, { method: 'DELETE' }),
};
