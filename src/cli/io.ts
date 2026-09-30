/** Everything a command touches in its environment, injectable for tests. */
export interface CliIO {
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
  /** Whether stdout is a terminal (colors, spinners, prompts). */
  readonly isTTY: boolean;
  readonly env: NodeJS.ProcessEnv;
  readonly cwd: string;
  /** Read all of stdin (hooks receive their event there). */
  readonly readStdin: () => Promise<string>;
  /** Ask a yes/no question on the terminal. Resolves false when there is no terminal. */
  readonly confirm: (question: string) => Promise<boolean>;
}

/** A closed pipe (`skill-scanner ... | head`) ends the process quietly instead of with a stack trace. */
function exitOnBrokenPipe(stream: NodeJS.WriteStream): void {
  stream.on("error", (e: NodeJS.ErrnoException) => {
    if (e.code === "EPIPE") process.exit(process.exitCode ?? 0);
    throw e;
  });
}

export function processIO(): CliIO {
  exitOnBrokenPipe(process.stdout);
  exitOnBrokenPipe(process.stderr);
  return {
    stdout: (t) => {
      process.stdout.write(t);
    },
    stderr: (t) => {
      process.stderr.write(t);
    },
    isTTY: Boolean(process.stdout.isTTY),
    env: process.env,
    cwd: process.cwd(),
    readStdin: async () => {
      if (process.stdin.isTTY) return "";
      const chunks: Buffer[] = [];
      for await (const c of process.stdin) chunks.push(c as Buffer);
      return Buffer.concat(chunks).toString("utf8");
    },
    confirm: async (question) => {
      if (!process.stdin.isTTY || !process.stderr.isTTY) return false;
      const { createInterface } = await import("node:readline/promises");
      const rl = createInterface({ input: process.stdin, output: process.stderr });
      try {
        const answer = await rl.question(`${question} [y/N] `);
        return /^y(es)?$/i.test(answer.trim());
      } finally {
        rl.close();
      }
    },
  };
}

/** Whether to emit ANSI colors: a TTY, no NO_COLOR, not a dumb terminal, or FORCE_COLOR set. */
export function useColor(io: Pick<CliIO, "isTTY" | "env">): boolean {
  if (io.env.FORCE_COLOR && io.env.FORCE_COLOR !== "0") return true;
  if (io.env.NO_COLOR !== undefined && io.env.NO_COLOR !== "") return false;
  return io.isTTY && io.env.TERM !== "dumb";
}
