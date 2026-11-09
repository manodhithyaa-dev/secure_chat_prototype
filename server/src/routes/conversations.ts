import { Router } from 'express';
import type { Pool } from 'pg';
import { requireAuth } from '../auth/middleware';
import {
  buildConversation,
  findUserById,
  getOrCreateDirectConversation,
  listConversations
} from '../db/queries';
import { presence } from '../presence';
import { isUuid } from '../validate';
import { asyncRoute } from './util';

export function conversationsRouter(pool: Pool): Router {
  const router = Router();

  router.get(
    '/',
    requireAuth(pool),
    asyncRoute(async (req, res) => {
      const conversations = await listConversations(pool, req.session!.userId, presence.isOnline);
      res.json({ conversations });
    })
  );

  router.post(
    '/',
    requireAuth(pool),
    asyncRoute(async (req, res) => {
      const body = (req.body ?? {}) as Record<string, unknown>;
      const viewerId = req.session!.userId;
      const otherUserId = body.otherUserId;

      if (!isUuid(otherUserId)) {
        res.status(400).json({ error: 'otherUserId must be a valid user id.' });
        return;
      }
      if (otherUserId === viewerId) {
        res.status(400).json({ error: 'Cannot create a conversation with yourself.' });
        return;
      }
      const other = await findUserById(pool, otherUserId);
      if (!other) {
        res.status(404).json({ error: 'User not found.' });
        return;
      }

      const { id } = await getOrCreateDirectConversation(pool, viewerId, otherUserId);
      const { rows } = await pool.query('SELECT id, type, updated_at FROM conversations WHERE id = $1', [id]);
      const conversation = await buildConversation(
        pool,
        rows[0],
        viewerId,
        presence.isOnline
      );
      res.json({ conversation });
    })
  );

  return router;
}
