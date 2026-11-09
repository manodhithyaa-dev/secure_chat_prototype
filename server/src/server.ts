import express, { type NextFunction, type Request, type Response } from 'express';
import http from 'http';
import path from 'path';
import type { AddressInfo } from 'net';
import { Server } from 'socket.io';
import { purgeExpiredSessions } from './auth/sessions';
import { config } from './config';
import { closePool, getPool } from './db/pool';
import { runMigrations } from './db/migrate';
import { sweepExpired } from './db/queries';
import { authRouter, meRouter } from './routes/auth';
import { conversationsRouter } from './routes/conversations';
import { usersRouter } from './routes/users';
import { registerSocketHandlers } from './socket';

export interface RunningServer {
  app: express.Express;
  httpServer: http.Server;
  io: Server;
  port: number;
  close: () => Promise<void>;
}

export async function startServer(options: { port?: number; migrate?: boolean } = {}): Promise<RunningServer> {
  const pool = getPool();
  if (options.migrate !== false) {
    await runMigrations(pool);
  }

  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '64kb' }));

  app.get('/health', (_req, res) => {
    res.json({ ok: true });
  });

  app.use('/api/auth', authRouter(pool));
  app.use('/api', meRouter(pool));
  app.use('/api/users', usersRouter(pool));
  app.use('/api/conversations', conversationsRouter(pool));
  app.use('/api', (_req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  const clientDir = path.join(__dirname, '..', '..', 'client');
  app.use(express.static(clientDir));

  const httpServer = http.createServer(app);
  const io = new Server(httpServer, {
    cors: { origin: true, methods: ['GET', 'POST'] }
  });
  registerSocketHandlers(io, pool);

  const port = options.port ?? config.port;
  await new Promise<void>((resolve) => httpServer.listen(port, resolve));

  const sweeper = setInterval(() => {
    sweepExpired(pool)
      .then(() => purgeExpiredSessions(pool))
      .catch(() => undefined);
  }, 60_000);
  sweeper.unref();

  console.log(`Secure chat relay listening on http://localhost:${port}`);

  const close = async (): Promise<void> => {
    clearInterval(sweeper);
    await new Promise<void>((resolve) => io.close(() => resolve()));
    await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    await closePool();
  };

  return {
    app,
    httpServer,
    io,
    port: (httpServer.address() as AddressInfo).port,
    close
  };
}

if (require.main === module) {
  startServer().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
