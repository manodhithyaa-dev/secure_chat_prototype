const env = process.env;

export const config = {
  get port(): number {
    return Number(env.PORT) || 3000;
  },
  get databaseUrl(): string {
    return env.DATABASE_URL || '';
  },
  get cookieSecure(): boolean {
    return env.COOKIE_SECURE === 'true';
  },
  get sessionTtlDays(): number {
    const value = Number(env.SESSION_TTL_DAYS);
    return Number.isFinite(value) && value > 0 ? value : 30;
  },
  get messageTtlDays(): number {
    const value = Number(env.MESSAGE_TTL_DAYS);
    return Number.isFinite(value) && value > 0 ? value : 30;
  },
  get nodeEnv(): string {
    return env.NODE_ENV || 'development';
  },
  cookieName: 'sc_session'
};
