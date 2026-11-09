import type { NextFunction, Request, Response } from 'express';
import type { Pool } from 'pg';
import { tokenFromCookies } from './cookies';
import { validateSession, type SessionInfo } from './sessions';

declare module 'express-serve-static-core' {
  interface Request {
    session?: SessionInfo;
  }
}

export function requireAuth(pool: Pool) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const token = tokenFromCookies(req.headers.cookie);
      const session = await validateSession(pool, token);
      if (!session) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }
      req.session = session;
      next();
    } catch (error) {
      next(error);
    }
  };
}
