import { signToken, TokenPayload } from '../../src/lib/jwt';

export function createAuthToken(overrides: Partial<TokenPayload> = {}): string {
  const payload: TokenPayload = {
    userId: overrides.userId || 'test-user-id',
    email: overrides.email || 'test@examples.com',
    role: overrides.role || 'user',
  };
  return signToken(payload);
}

export function createAdminToken(userId?: string): string {
  return createAuthToken({ userId: userId, role: 'admin' });
}

export function createUserToken(userId?: string): string {
  return createAuthToken({ userId: userId, role: 'user' });
}

export function authHeader(token: string) {
  return `Bearer ${token}`;
}
