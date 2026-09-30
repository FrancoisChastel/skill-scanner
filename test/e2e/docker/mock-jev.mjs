// A stand-in for TypeSafe's System One endpoint: answers every choice question, logs each request.
import { appendFileSync } from "node:fs";
import { createServer } from "node:http";

const LOG = process.env.MOCK_LOG ?? "/tmp/jev-requests.jsonl";
const HIGH = new Set(["prompt_injection", "data_exfiltration"]);

createServer((req, res) => {
  let body = "";
  req.on("data", (c) => {
    body += c;
  });
  req.on("end", () => {
    let parsed = {};
    try {
      parsed = JSON.parse(body);
    } catch {}
    const { authorization, ...headers } = req.headers;
    appendFileSync(
      LOG,
      `${JSON.stringify({ path: req.url, method: req.method, hasAuth: Boolean(authorization), authScheme: String(authorization ?? "").split(" ")[0], headers, body: parsed })}\n`,
    );
    const answers = {};
    for (const [id, q] of Object.entries(parsed.questions ?? {})) {
      const p = HIGH.has(id) ? 0.9 : 0.01;
      answers[id] =
        q.type === "choice"
          ? { type: "choice", choice: p >= 0.5 ? "true" : "false", probabilities: { true: p, false: 1 - p }, confidence: 0.8 }
          : { type: q.type, noul: p };
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ model: "jev-latest", answers, usage: { input_tokens: 100, output_tokens: 8 } }));
  });
}).listen(8787, "127.0.0.1", () => console.log("mock jev on 127.0.0.1:8787"));
