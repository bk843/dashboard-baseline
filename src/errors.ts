/** Errors that are safe to show the client. Anything else becomes a generic 500. */
export class HttpError extends Error {
  constructor(
    public readonly status: 400 | 401 | 402 | 403 | 404 | 409 | 413 | 415 | 429 | 503,
    public readonly code: string,
    public readonly publicMessage?: string,
  ) {
    super(code);
  }
}
