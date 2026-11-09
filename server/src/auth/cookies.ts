import { config } from '../config';

export function parseCookieHeader(header: string | undefined): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!header) return cookies;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index < 1) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (name && !(name in cookies)) {
      try {
        cookies[name] = decodeURIComponent(value);
      } catch {
        cookies[name] = value;
      }
    }
  }
  return cookies;
}

interface CookieOptions {
  path?: string;
  maxAge?: number;
  httpOnly?: boolean;
  sameSite?: 'Strict' | 'Lax';
  secure?: boolean;
}

export function serializeCookie(name: string, value: string, options: CookieOptions = {}): string {
  let cookie = `${name}=${encodeURIComponent(value)}`;
  if (options.path) cookie += `; Path=${options.path}`;
  if (options.maxAge !== undefined) cookie += `; Max-Age=${Math.floor(options.maxAge)}`;
  if (options.httpOnly) cookie += '; HttpOnly';
  if (options.sameSite) cookie += `; SameSite=${options.sameSite}`;
  if (options.secure) cookie += '; Secure';
  return cookie;
}

export function sessionCookie(token: string): string {
  return serializeCookie(config.cookieName, token, {
    path: '/',
    httpOnly: true,
    sameSite: 'Strict',
    secure: config.cookieSecure,
    maxAge: config.sessionTtlDays * 86_400
  });
}

export function clearSessionCookie(): string {
  return serializeCookie(config.cookieName, '', {
    path: '/',
    httpOnly: true,
    sameSite: 'Strict',
    secure: config.cookieSecure,
    maxAge: 0
  });
}

export function tokenFromCookies(header: string | undefined): string | undefined {
  return parseCookieHeader(header)[config.cookieName];
}
