import express from 'express';
import http from 'http';
import path from 'path';
import { Server } from 'socket.io';
import { registerSocketHandlers } from './socket';

const app = express();
const httpServer = http.createServer(app);
const io = new Server(httpServer, {
  cors: { origin: true, methods: ['GET', 'POST'] }
});

registerSocketHandlers(io);

const clientDir = path.join(__dirname, '..', '..', 'client');
app.use(express.static(clientDir));

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

const port = Number(process.env.PORT) || 3000;
httpServer.listen(port, () => {
  console.log(`Secure chat relay listening on http://localhost:${port}`);
});
