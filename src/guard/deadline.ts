/**
 * Run work under a deadline. A harness that times a hook out lets the call through, so every
 * hook stops waiting before its harness does and decides with what it has.
 */

export type DeadlineOutcome<T> =
  | { readonly status: "ok"; readonly value: T }
  | { readonly status: "timeout" }
  | { readonly status: "error"; readonly error: unknown };

export async function withDeadline<T>(
  ms: number,
  parent: AbortSignal | undefined,
  run: (signal: AbortSignal) => Promise<T>,
): Promise<DeadlineOutcome<T>> {
  const controller = new AbortController();
  const onAbort = (): void => controller.abort(parent?.reason);
  if (parent?.aborted) return { status: "error", error: parent.reason ?? new Error("aborted") };
  parent?.addEventListener("abort", onAbort, { once: true });
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<DeadlineOutcome<T>>((resolve) => {
    timer = setTimeout(() => {
      controller.abort(new Error(`deadline of ${ms} ms passed`));
      resolve({ status: "timeout" });
    }, ms);
  });
  const work = (async (): Promise<DeadlineOutcome<T>> => {
    try {
      return { status: "ok", value: await run(controller.signal) };
    } catch (error) {
      return { status: "error", error };
    }
  })();
  try {
    return await Promise.race([work, timeout]);
  } finally {
    clearTimeout(timer);
    parent?.removeEventListener("abort", onAbort);
  }
}
