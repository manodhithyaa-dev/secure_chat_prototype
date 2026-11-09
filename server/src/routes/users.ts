import { Router } from 'express';
import type { Pool } from 'pg';
import { requireAuth } from '../auth/middleware';
import { searchUsers } from '../db/queries';
import { presence } from '../presence';
import { asyncRoute } from './util';

export function usersRouter(pool: Pool): Router {
  const router = Router();

  router.get(
    '/search',
    requireAuth(pool),
    asyncRoute(async (req, res) => {
      const query = typeof req.query.q === 'string' ? req.query.q.trim() : '';
      if (!query) {
        res.json({ users: [] });
        return;
      }
      if (query.length > 64) {
        res.status(400).json({ error: 'Query must be at most 64 characters.' });
        return;
      }
      const users = await searchUsers(pool, query.slice(0, 64), req.session!.userId);
      res.json({ users });
    })
  );

  return router;
}

export function isOnlineViaPresence(userId: string): boolean {
  return presence.isOnline(userId);
}
