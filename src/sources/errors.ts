/** A source that cannot be parsed or fetched. Messages name the source but never carry credentials. */
export class SourceError extends Error {
  override readonly name: string = "SourceError";
}

/** A source form skill-scanner recognises but does not fetch (direct URLs, well-known endpoints). */
export class UnsupportedSourceError extends SourceError {
  override readonly name = "UnsupportedSourceError";
}

/** A tarball that is malformed, too large, or tries to write outside its root. */
export class TarError extends SourceError {
  override readonly name = "TarError";
}

/**
 * Hide the user-info part of URLs (`https://token@host`, `https://user:p@ss@host`) in any text.
 * User-info runs to the last `@` before the path, so a password containing `@` is hidden whole.
 */
export function redactCredentials(text: string): string {
  return text.replace(/\b([a-z][a-z0-9+.-]*:\/\/)([^/\s]*)@/gi, (_m, scheme: string, user: string) =>
    user === "git" ? `${scheme}git@` : `${scheme}***@`,
  );
}
