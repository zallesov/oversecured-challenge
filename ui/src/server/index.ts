import { existsSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import express, {
  type ErrorRequestHandler,
  type NextFunction,
  type Request,
  type Response,
} from "express";

import { runMigrations } from "./db.js";
import authRoutes from "./routes/auth.js";
import runRoutes from "./routes/runs.js";
import { startStatusSync } from "./services/status-sync.js";

export const app = express();

app.use(express.json({ limit: "1mb" }));

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.use(authRoutes);
app.use(runRoutes);

if (process.env.NODE_ENV === "production") {
  const clientDir = path.resolve(process.cwd(), "dist/client");
  const indexHtml = path.join(clientDir, "index.html");

  if (existsSync(indexHtml)) {
    app.use(express.static(clientDir));
    app.use((req: Request, res: Response, next: NextFunction) => {
      if (req.method !== "GET" || req.path.startsWith("/api")) {
        next();
        return;
      }
      res.sendFile(indexHtml);
    });
  }
}

const errorHandler: ErrorRequestHandler = (error, _req, res, _next) => {
  console.error(error);
  res.status(500).json({
    error: "Internal server error",
    detail: error instanceof Error ? error.message : String(error),
  });
};

app.use(errorHandler);

export async function startServer(): Promise<void> {
  await runMigrations();
  startStatusSync(Number(process.env.STATUS_SYNC_INTERVAL_MS ?? 1000));

  const port = Number(process.env.PORT ?? 3000);
  app.listen(port, () => {
    console.log(`UI API listening on port ${port}`);
  });
}

const isEntrypoint =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isEntrypoint) {
  startServer().catch((error) => {
    console.error("Failed to start UI API:", error);
    process.exit(1);
  });
}
