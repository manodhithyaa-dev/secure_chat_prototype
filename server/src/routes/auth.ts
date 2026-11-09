import { Router } from 'express';
import type { Pool } from 'pg';
import { requireAuth } from '../auth/middleware';
import { clearSessionCookie, sessionCookie, tokenFromCookies } from '../auth/cookies';
import { hashPassword, verifyPassword } from '../auth/passwords';
import { createSession, revokeSession } from '../auth/sessions';
import { fingerprintFromPublicKey, isValidPublicKey } from '../identity';
import { createUser, findUserById, findUserByIdentifier, getUserPublicKey, touchLastSeen } from '../db/queries';
import type { AuthedUser } from '../types';
import {
  isValidDisplayName,
  isValidEmail,
  isValidPassword,
  isValidUsername
} from '../validate';
import { asyncRoute } from './util';

async function toAuthedUser(pool: Pool, userId: string): Promise<AuthedUser | null> {
  const user = await findUserById(pool, userId);
  if (!user) return null;
  const publicKey = await getUserPublicKey(pool, user.id);
  return {
    userId: user.id,
    username: user.username,
    displayName: user.display_name,
    email: user.email,
    avatarUrl: user.avatar_url,
    publicKey,
    fingerprint: publicKey ? fingerprintFromPublicKey(publicKey) : null,
    createdAt: new Date(user.created_at).toISOString()
  };
}

export function authRouter(pool: Pool): Router {
  const router = Router();

  router.post(
    '/register',
    asyncRoute(async (req, res) => {
      const body = (req.body ?? {}) as Record<string, unknown>;
      const username = typeof body.username === 'string' ? body.username.trim().toLowerCase() : '';
      const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';

      if (!isValidUsername(username)) {
        res.status(400).json({ error: 'Username must be 3-32 characters (letters, numbers, underscore).' });
        return;
      }
      if (!isValidEmail(email)) {
        res.status(400).json({ error: 'A valid email address is required.' });
        return;
      }
      if (!isValidPassword(body.password)) {
        res.status(400).json({ error: 'Password must be 8-128 characters.' });
        return;
      }
      if (!isValidDisplayName(body.displayName)) {
        res.status(400).json({ error: 'Display name must be at most 64 characters.' });
        return;
      }
      if (!isValidPublicKey(body.publicKey)) {
        res.status(400).json({ error: 'Invalid public key.' });
        return;
      }

      const passwordHash = await hashPassword(body.password as string);
      const displayName =
        typeof body.displayName === 'string' && body.displayName.trim()
          ? body.displayName.trim()
          : username;

      let user;
      try {
        user = await createUser(pool, {
          username,
          email,
          passwordHash,
          displayName,
          publicKey: body.publicKey as string
        });
      } catch (error) {
        if ((error as { code?: string }).code === '23505') {
          res.status(409).json({ error: 'Username or email already taken.' });
          return;
        }
        throw error;
      }

      const { token } = await createSession(pool, user.id);
      res.setHeader('Set-Cookie', sessionCookie(token));
      res.status(201).json({ user: await toAuthedUser(pool, user.id) });
    })
  );

  router.post(
    '/login',
    asyncRoute(async (req, res) => {
      const body = (req.body ?? {}) as Record<string, unknown>;
      const identifier = typeof body.identifier === 'string' ? body.identifier.trim().toLowerCase() : '';
      const password = typeof body.password === 'string' ? body.password : '';

      if (!identifier || !password) {
        res.status(400).json({ error: 'Username/email and password are required.' });
        return;
      }

      const user = await findUserByIdentifier(pool, identifier);
      const valid = user ? await verifyPassword(user.password_hash, password) : false;
      if (!user || !valid) {
        res.status(401).json({ error: 'Invalid credentials.' });
        return;
      }

      const { token } = await createSession(pool, user.id);
      await touchLastSeen(pool, user.id);
      res.setHeader('Set-Cookie', sessionCookie(token));
      res.json({ user: await toAuthedUser(pool, user.id) });
    })
  );

  router.post(
    '/logout',
    asyncRoute(async (req, res) => {
      const token = tokenFromCookies(req.headers.cookie);
      await revokeSession(pool, token);
      res.setHeader('Set-Cookie', clearSessionCookie());
      res.status(204).end();
    })
  );

  return router;
}

export function meRouter(pool: Pool): Router {
  const router = Router();
  router.get(
    '/me',
    requireAuth(pool),
    asyncRoute(async (req, res) => {
      const user = await toAuthedUser(pool, req.session!.userId);
      if (!user) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }
      await touchLastSeen(pool, user.userId);
      res.json({ user });
    })
  );
  router.put(
    '/me/public-key',
    requireAuth(pool),
    asyncRoute(async (req, res) => {
      const body = (req.body ?? {}) as Record<string, unknown>;
      if (!isValidPublicKey(body.publicKey)) {
        res.status(400).json({ error: 'Invalid public key.' });
        return;
      }
      const userId = req.session!.userId;
      await pool.query(
        'UPDATE devices SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL',
        [userId]
      );
      await pool.query('INSERT INTO devices (user_id, public_key) VALUES ($1, $2)', [
        userId,
        body.publicKey as string
      ]);
      res.json({
        ok: true,
        publicKey: body.publicKey,
        fingerprint: fingerprintFromPublicKey(body.publicKey as string)
      });
    })
  );
  return router;
}
