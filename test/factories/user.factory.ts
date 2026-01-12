import { hashPassword } from '../../src/lib/password';

let counter = 0;

export interface UserFactoryInput {
  email?: string;
  password?: string;
  name?: string;
  dateOfBirth?: string;
  credits?: number;
  role?: 'user' | 'admin';
}

export interface CreateUserPayload {
  email: string;
  password: string;
  name: string;
  dateOfBirth: string;
}

export function createUserPayload(overrides: UserFactoryInput = {}): CreateUserPayload {
  counter++;
  return {
    email: overrides.email || `testuser${counter}@example.com`,
    password: overrides.password || 'Password1!',
    name: overrides.name || `Test User ${counter}`,
    dateOfBirth: overrides.dateOfBirth || '1996-01-01',
  };
}

export async function buildUserForDb(overrides: UserFactoryInput = {}) {
  const payload = createUserPayload(overrides);
  const passwordHash = await hashPassword(payload.password);

  return {
    email: payload.email.toLowerCase(),
    passwordHash,
    name: payload.name,
    dateOfBirth: payload.dateOfBirth,
    role: overrides.role || 'user',
  };
}

export function resetUserFactory() {
  counter = 0;
}
