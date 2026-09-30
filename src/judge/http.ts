/**
 * One JSON POST to a jev endpoint, with a per-attempt deadline and retries on 429, 529, 5xx and
 * network failures. Redirects are refused: following one would carry the key to another host.
 * Error messages are built here from status codes and fixed text, so they never echo the key.
 */

/** Anything shaped like fetch. Structural so tests and hosts can inject a plain function. */
export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

export type JudgeErrorCode = "http" | "redirect" | "timeout" | "network" | "cancelled" | "invalid_response";

export class JudgeError extends Error {
  override readonly name = "JudgeError";
  readonly code: JudgeErrorCode;
  readonly retryable: boolean;
  readonly status: number | undefined;

  constructor(message: string, code: JudgeErrorCode, retryable = false, status?: number) {
    super(message);
    this.code = code;
    this.retryable = retryable;
    this.status = status;
  }
}

export interface PostOptions {
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
  /** Deadline for each attempt, including reading the response. */
  readonly timeoutMs: number;
  readonly maxRetries: number;
  /** Base backoff, doubled per retry with jitter. */
  readonly retryDelayMs: number;
  readonly fetch: FetchLike;
  readonly signal?: AbortSignal;
}

/** POST `body` and return the parsed JSON response. Throws JudgeError. */
export async function postJson(opts: PostOptions): Promise<unknown> {
  let last = new JudgeError("no attempt was made", "network");
  for (let attempt = 0; attempt <= opts.maxRetries; attempt += 1) {
    if (attempt > 0) await delay(opts.retryDelayMs * 2 ** (attempt - 1) * (0.5 + Math.random()), opts.signal);
    try {
      return await attemptOnce(opts);
    } catch (e) {
      last = e instanceof JudgeError ? e : new JudgeError("unexpected transport error", "network");
      if (!last.retryable) throw last;
    }
  }
  throw last;
}

async function attemptOnce(opts: PostOptions): Promise<unknown> {
  if (opts.signal?.aborted) throw cancelled();
  const ctrl = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    ctrl.abort();
  }, opts.timeoutMs);
  const onAbort = (): void => ctrl.abort();
  opts.signal?.addEventListener("abort", onAbort, { once: true });
  const why = (e: unknown): JudgeError =>
    timedOut
      ? new JudgeError(`timed out after ${opts.timeoutMs} ms`, "timeout")
      : opts.signal?.aborted
        ? cancelled()
        : e instanceof JudgeError
          ? e
          : new JudgeError(`could not reach ${hostOf(opts.url)} (${causeCode(e)})`, "network", true);
  try {
    const res = await opts.fetch(opts.url, {
      method: "POST",
      headers: { ...opts.headers },
      body: opts.body,
      redirect: "manual",
      signal: ctrl.signal,
    });
    checkStatus(res);
    return await readJson(res);
  } catch (e) {
    throw why(e);
  } finally {
    clearTimeout(timer);
    opts.signal?.removeEventListener("abort", onAbort);
  }
}

function checkStatus(res: Response): void {
  if (res.ok && res.type !== "opaqueredirect") return;
  discard(res);
  if (res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400))
    throw new JudgeError(
      `responded with a redirect (${res.status}); refused so the key is not sent elsewhere`,
      "redirect",
      false,
      res.status,
    );
  const retryable = res.status === 429 || res.status === 529 || res.status >= 500;
  throw new JudgeError(`responded ${res.status}${statusHint(res.status)}`, "http", retryable, res.status);
}

async function readJson(res: Response): Promise<unknown> {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new JudgeError("returned a response that is not JSON", "invalid_response", false, res.status);
  }
}

function statusHint(status: number): string {
  if (status === 401 || status === 403) return " (check the API key)";
  if (status === 402) return " (check the account's credits)";
  if (status === 404) return " (check judge.model and judge.baseUrl)";
  if (status === 429) return " (rate limited)";
  return "";
}

/** Release the connection without reading a body we will not use. */
function discard(res: Response): void {
  res.body?.cancel().catch(() => undefined);
}

const cancelled = (): JudgeError => new JudgeError("cancelled", "cancelled");

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "the endpoint";
  }
}

/** A system error code such as ECONNREFUSED, when there is one; never free text from the error. */
function causeCode(e: unknown): string {
  const cause = typeof e === "object" && e !== null && "cause" in e ? (e as { cause: unknown }).cause : undefined;
  const code = typeof cause === "object" && cause !== null && "code" in cause ? (cause as { code: unknown }).code : undefined;
  return typeof code === "string" && /^[A-Z][A-Z0-9_]{1,40}$/.test(code) ? code : "network error";
}

function delay(ms: number, signal: AbortSignal | undefined): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(cancelled());
      return;
    }
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(cancelled());
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
