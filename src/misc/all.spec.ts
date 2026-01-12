// ═══════════════════════════════════════════════════════════════════════════
// FILE: test/dbTestUtils.ts
// ═══════════════════════════════════════════════════════════════════════════
import { pool } from '../src/db/pool';

export async function cleanupDatabase(): Promise<void> {
  await pool.query('DELETE FROM users');
}

export async function closeDatabase(): Promise<void> {
  await pool.end();
}

// ═══════════════════════════════════════════════════════════════════════════
// FILE: test/env.test.ts
// ═══════════════════════════════════════════════════════════════════════════
import { describe, it, expect } from 'vitest';
import { env } from '../src/lib/env';

describe('Environment Configuration', () => {
  it('should load environment variables', () => {
    expect(env).toBeDefined();
    expect(env.NODE_ENV).toBeDefined();
    expect(env.DB_HOST).toBeDefined();
    expect(env.DB_NAME).toBeDefined();
  });

  it('should have valid database configuration', () => {
    expect(env.DB_PORT).toBeGreaterThan(0);
    expect(env.DB_POOL_MAX).toBeGreaterThan(0);
  });

  it('should have JWT secret configured', () => {
    expect(env.JWT_SECRET).toBeDefined();
    expect(env.JWT_SECRET.length).toBeGreaterThanOrEqual(32);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// FILE: test/transaction.test.ts
// ═══════════════════════════════════════════════════════════════════════════
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { pool } from '../src/db/pool';
import { ensureSchema } from '../src/db/schema';
import { withTransaction } from '../src/db/transaction';
import { query } from '../src/db/query';
import { UserRepository } from '../src/repositories/UserRepository';
import { hashPassword } from '../src/lib/password';

describe('Transaction Tests', () => {
  beforeAll(async () => {
    await ensureSchema(pool);
  });

  afterAll(async () => {
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query('DELETE FROM users');
  });

  it('should commit transaction on success', async () => {
    const result = await withTransaction(pool, async (tx) => {
      const passwordHash = await hashPassword('Password123!');
      const repo = new UserRepository(tx);
      const user = await repo.create({
        email: 'test@example.com',
        passwordHash,
        name: 'Test User',
      });
      return user;
    });

    expect(result).toBeDefined();
    expect(result.email).toBe('test@example.com');

    // Verify in database
    const dbResult = await query(pool, 'SELECT * FROM users WHERE email = $1', [
      'test@example.com',
    ]);
    expect(dbResult.rows.length).toBe(1);
  });

  it('should rollback transaction on error', async () => {
    try {
      await withTransaction(pool, async (tx) => {
        const passwordHash = await hashPassword('Password123!');
        const repo = new UserRepository(tx);
        await repo.create({
          email: 'rollback@example.com',
          passwordHash,
          name: 'Rollback User',
        });

        // Force an error
        throw new Error('Intentional error');
      });
    } catch (err) {
      expect(err).toBeDefined();
    }

    // Verify NOT in database
    const dbResult = await query(pool, 'SELECT * FROM users WHERE email = $1', [
      'rollback@example.com',
    ]);
    expect(dbResult.rows.length).toBe(0);
  });

  it('should support nested transactions', async () => {
    const result = await withTransaction(pool, async (tx) => {
      const passwordHash = await hashPassword('Password123!');
      const repo = new UserRepository(tx);

      const user1 = await repo.create({
        email: 'user1@example.com',
        passwordHash,
        name: 'User 1',
      });

      const user2 = await repo.create({
        email: 'user2@example.com',
        passwordHash,
        name: 'User 2',
      });

      return { user1, user2 };
    });

    expect(result.user1.email).toBe('user1@example.com');
    expect(result.user2.email).toBe('user2@example.com');

    // Verify both in database
    const dbResult = await query(pool, 'SELECT * FROM users');
    expect(dbResult.rows.length).toBe(2);
  });

  it('should handle serializable isolation level', async () => {
    const passwordHash = await hashPassword('Password123!');

    const result = await withTransaction(
      pool,
      async (tx) => {
        const repo = new UserRepository(tx);
        return repo.create({
          email: 'serializable@example.com',
          passwordHash,
          name: 'Serializable User',
        });
      },
      { isolationLevel: 'SERIALIZABLE' },
    );

    expect(result.email).toBe('serializable@example.com');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// FILE: test/user.respository.test.ts
// ═══════════════════════════════════════════════════════════════════════════
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { pool } from '../src/db/pool';
import { ensureSchema } from '../src/db/schema';
import { UserRepository } from '../src/repositories/UserRepository';
import { hashPassword } from '../src/lib/password';

describe('UserRepository', () => {
  const repo = new UserRepository(pool);

  beforeAll(async () => {
    await ensureSchema(pool);
  });

  afterAll(async () => {
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query('DELETE FROM users');
  });

  describe('create', () => {
    it('should create a new user', async () => {
      const passwordHash = await hashPassword('Password123!');
      const user = await repo.create({
        email: 'test@example.com',
        passwordHash,
        name: 'Test User',
        dateOfBirth: '1990-01-01',
        credits: 100,
      });

      expect(user).toBeDefined();
      expect(user.id).toBeDefined();
      expect(user.email).toBe('test@example.com');
      expect(user.name).toBe('Test User');
      expect(user.dateOfBirth).toBe('1990-01-01');
      expect(user.credits).toBe(100);
      expect(user.passwordHash).toBe(passwordHash);
    });

    it('should normalize email to lowercase', async () => {
      const passwordHash = await hashPassword('Password123!');
      const user = await repo.create({
        email: 'Test@Example.COM',
        passwordHash,
        name: 'Test User',
      });

      expect(user.email).toBe('test@example.com');
    });

    it('should throw ConflictError for duplicate email', async () => {
      const passwordHash = await hashPassword('Password123!');

      await repo.create({
        email: 'duplicate@example.com',
        passwordHash,
        name: 'User 1',
      });

      await expect(
        repo.create({
          email: 'duplicate@example.com',
          passwordHash,
          name: 'User 2',
        }),
      ).rejects.toThrow();
    });

    it('should set default values for optional fields', async () => {
      const passwordHash = await hashPassword('Password123!');
      const user = await repo.create({
        email: 'defaults@example.com',
        passwordHash,
        name: 'Defaults User',
      });

      expect(user.credits).toBe(0);
      expect(user.dateOfBirth).toBeNull();
      expect(user.role).toBe('user');
    });
  });

  describe('findById', () => {
    it('should find user by ID', async () => {
      const passwordHash = await hashPassword('Password123!');
      const created = await repo.create({
        email: 'findbyid@example.com',
        passwordHash,
        name: 'Find By ID',
      });

      const found = await repo.findById(created.id);

      expect(found).toBeDefined();
      expect(found!.id).toBe(created.id);
      expect(found!.email).toBe(created.email);
    });

    it('should return null for non-existent ID', async () => {
      const found = await repo.findById('00000000-0000-0000-0000-000000000000');
      expect(found).toBeNull();
    });
  });

  describe('findByEmail', () => {
    it('should find user by email', async () => {
      const passwordHash = await hashPassword('Password123!');
      const created = await repo.create({
        email: 'findbyemail@example.com',
        passwordHash,
        name: 'Find By Email',
      });

      const found = await repo.findByEmail('findbyemail@example.com');

      expect(found).toBeDefined();
      expect(found!.id).toBe(created.id);
      expect(found!.email).toBe('findbyemail@example.com');
    });

    it('should be case-insensitive', async () => {
      const passwordHash = await hashPassword('Password123!');
      await repo.create({
        email: 'CaseTest@Example.com',
        passwordHash,
        name: 'Case Test',
      });

      const found = await repo.findByEmail('casetest@example.com');

      expect(found).toBeDefined();
      expect(found!.email).toBe('casetest@example.com');
    });

    it('should return null for non-existent email', async () => {
      const found = await repo.findByEmail('nonexistent@example.com');
      expect(found).toBeNull();
    });
  });

  describe('update', () => {
    it('should update user fields', async () => {
      const passwordHash = await hashPassword('Password123!');
      const created = await repo.create({
        email: 'update@example.com',
        passwordHash,
        name: 'Original Name',
        credits: 100,
      });

      const updated = await repo.update(created.id, {
        name: 'Updated Name',
        credits: 200,
      });

      expect(updated).toBeDefined();
      expect(updated!.name).toBe('Updated Name');
      expect(updated!.credits).toBe(200);
      expect(updated!.email).toBe(created.email);
    });

    it('should update only specified fields', async () => {
      const passwordHash = await hashPassword('Password123!');
      const created = await repo.create({
        email: 'partial@example.com',
        passwordHash,
        name: 'Original Name',
        credits: 100,
      });

      const updated = await repo.update(created.id, {
        name: 'New Name',
      });

      expect(updated!.name).toBe('New Name');
      expect(updated!.credits).toBe(100); // unchanged
    });

    it('should return null for non-existent user', async () => {
      const updated = await repo.update('00000000-0000-0000-0000-000000000000', {
        name: 'Test',
      });

      expect(updated).toBeNull();
    });

    it('should update email with case normalization', async () => {
      const passwordHash = await hashPassword('Password123!');
      const created = await repo.create({
        email: 'original@example.com',
        passwordHash,
        name: 'User',
      });

      const updated = await repo.update(created.id, {
        email: 'NewEmail@Example.COM',
      });

      expect(updated!.email).toBe('newemail@example.com');
    });
  });

  describe('delete', () => {
    it('should delete user', async () => {
      const passwordHash = await hashPassword('Password123!');
      const created = await repo.create({
        email: 'delete@example.com',
        passwordHash,
        name: 'Delete Me',
      });

      const deleted = await repo.delete(created.id);
      expect(deleted).toBe(true);

      const found = await repo.findById(created.id);
      expect(found).toBeNull();
    });

    it('should return false for non-existent user', async () => {
      const deleted = await repo.delete('00000000-0000-0000-0000-000000000000');
      expect(deleted).toBe(false);
    });
  });

  describe('list', () => {
    it('should return empty array when no users exist', async () => {
      const users = await repo.list();
      expect(users).toEqual([]);
    });

    it('should list all users', async () => {
      const passwordHash = await hashPassword('Password123!');

      await repo.create({
        email: 'user1@example.com',
        passwordHash,
        name: 'User 1',
      });

      await repo.create({
        email: 'user2@example.com',
        passwordHash,
        name: 'User 2',
      });

      const users = await repo.list();

      expect(users.length).toBe(2);
      expect(users[0].email).toBeDefined();
      expect(users[1].email).toBeDefined();
    });

    it('should support limit', async () => {
      const passwordHash = await hashPassword('Password123!');

      for (let i = 1; i <= 5; i++) {
        await repo.create({
          email: `user${i}@example.com`,
          passwordHash,
          name: `User ${i}`,
        });
      }

      const users = await repo.list({ limit: 2 });

      expect(users.length).toBe(2);
    });

    it('should support offset', async () => {
      const passwordHash = await hashPassword('Password123!');

      for (let i = 1; i <= 5; i++) {
        await repo.create({
          email: `user${i}@example.com`,
          passwordHash,
          name: `User ${i}`,
        });
      }

      const users = await repo.list({ limit: 2, offset: 2 });

      expect(users.length).toBe(2);
    });

    it('should return users in descending order by creation date', async () => {
      const passwordHash = await hashPassword('Password123!');

      const user1 = await repo.create({
        email: 'first@example.com',
        passwordHash,
        name: 'First',
      });

      // Small delay to ensure different timestamps
      await new Promise((resolve) => setTimeout(resolve, 10));

      const user2 = await repo.create({
        email: 'second@example.com',
        passwordHash,
        name: 'Second',
      });

      const users = await repo.list();

      expect(users[0].id).toBe(user2.id); // newest first
      expect(users[1].id).toBe(user1.id);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// FILE: test/factories/user.factory.ts
// ═══════════════════════════════════════════════════════════════════════════
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
  dateOfBirth?: string;
  credits?: number;
}

export function createUserPayload(overrides: UserFactoryInput = {}): CreateUserPayload {
  counter++;
  return {
    email: overrides.email ?? `testuser${counter}@example.com`,
    password: overrides.password ?? 'Password123!',
    name: overrides.name ?? `Test User ${counter}`,
    dateOfBirth: overrides.dateOfBirth ?? '1990-01-15',
    credits: overrides.credits,
  };
}

export async function createUserForDb(overrides: UserFactoryInput = {}) {
  const payload = createUserPayload(overrides);
  return {
    email: payload.email,
    passwordHash: await hashPassword(payload.password),
    name: payload.name,
    dateOfBirth: payload.dateOfBirth,
    credits: overrides.credits ?? 0,
    role: overrides.role ?? 'user',
  };
}

export function resetUserFactory(): void {
  counter = 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// FILE: test/helpers/auth.helper.ts
// ═══════════════════════════════════════════════════════════════════════════
import { signToken, TokenPayload } from '../../src/lib/jwt';

export function createAuthToken(overrides: Partial<TokenPayload> = {}): string {
  const payload: TokenPayload = {
    userId: overrides.userId ?? '00000000-0000-0000-0000-000000000001',
    email: overrides.email ?? 'test@example.com',
    role: overrides.role ?? 'user',
  };
  return signToken(payload);
}

export function createAdminToken(userId?: string): string {
  return createAuthToken({
    userId: userId ?? '00000000-0000-0000-0000-000000000002',
    role: 'admin',
  });
}

export function createUserToken(userId?: string): string {
  return createAuthToken({
    userId: userId ?? '00000000-0000-0000-0000-000000000003',
    role: 'user',
  });
}

export function authHeader(token: string): string {
  return `Bearer ${token}`;
}

// ═══════════════════════════════════════════════════════════════════════════
// FILE: test/helpers/request.helpers.ts
// ═══════════════════════════════════════════════════════════════════════════
import request from 'supertest';
import { app } from '../../src/server';

export const api = request(app);

// ═══════════════════════════════════════════════════════════════════════════
// FILE: test/helpers/setup.ts
// ═══════════════════════════════════════════════════════════════════════════
import { pool } from '../../src/db/pool';
import { ensureSchema } from '../../src/db/schema';

export async function setupTestDatabase(): Promise<void> {
  await ensureSchema(pool);
}

export async function teardownTestDatabase(): Promise<void> {
  await pool.query('TRUNCATE users CASCADE');
}

export async function cleanupDatabase(): Promise<void> {
  await pool.query('DELETE FROM users');
}

export async function closeDatabase(): Promise<void> {
  await pool.end();
}

// ═══════════════════════════════════════════════════════════════════════════
// FILE: test/integeration/users.integration.test.ts
// ═══════════════════════════════════════════════════════════════════════════
import { pool } from '../../src/db/pool';
import { ensureSchema } from '../../src/db/schema';
import { UserRepository } from '../../src/repositories/UserRepository';
import { createUserPayload, resetUserFactory } from '../factories/user.factory';
import { authHeader, createAdminToken, createUserToken } from '../helpers/auth.helper';
import { api } from '../helpers/request.helpers';

const userRepo = new UserRepository(pool);

describe('User Integration Tests', () => {
  beforeAll(async () => {
    await ensureSchema(pool);
  });

  afterAll(async () => {
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query('DELETE FROM users');
    resetUserFactory();
  });

  // ─────────────────────────────────────────────────────────────────────────
  // POST /api/users (Registration) - PUBLIC
  // ─────────────────────────────────────────────────────────────────────────

  describe('POST /api/users (Registration)', () => {
    it('should register a new user successfully', async () => {
      const payload = createUserPayload();

      const res = await api.post('/api/users').send(payload);

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        email: payload.email.toLowerCase(),
        name: payload.name,
      });
      expect(res.body.data).toHaveProperty('id');
      expect(res.body.data).not.toHaveProperty('passwordHash');
      expect(res.body.data).not.toHaveProperty('password');

      // Verify database state
      const dbUser = await userRepo.findByEmail(payload.email);
      expect(dbUser).not.toBeNull();
      expect(dbUser!.email).toBe(payload.email.toLowerCase());
    });

    it('should return 400 for missing required fields', async () => {
      const res = await api.post('/api/users').send({});

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should return 400 for invalid email field', async () => {
      const payload = createUserPayload({ email: 'invalid' });
      const res = await api.post('/api/users').send(payload);

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');

      expect(res.body.error.details).toBeDefined();
      const emailError = res.body.error.details.find((d: any) => d.path === 'email');
      expect(emailError).toBeDefined();
      expect(emailError.message.toLowerCase()).toContain('email');
    });

    it('should return 400 for weak password', async () => {
      const payload = createUserPayload({ password: '123' });
      const res = await api.post('/api/users').send(payload);

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should return 409 for duplicate email registration', async () => {
      const payload = createUserPayload({ email: 'Test@example.com' });
      const payload2 = createUserPayload({ email: 'test@example.com' });

      await api.post('/api/users').send(payload);
      const res = await api.post('/api/users').send(payload2);

      expect(res.status).toBe(409);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('CONFLICT');
    });

    it('should handle case-insensitive email uniqueness', async () => {
      const payload1 = createUserPayload({ email: 'User@Example.COM' });
      const payload2 = createUserPayload({ email: 'user@example.com' });

      await api.post('/api/users').send(payload1);
      const res = await api.post('/api/users').send(payload2);

      expect(res.status).toBe(409);
    });

    it('should return 400 for invalid date of birth format', async () => {
      const payload = createUserPayload({ dateOfBirth: 'not-a-date' });
      const res = await api.post('/api/users').send(payload);

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // POST /api/users/login - PUBLIC
  // ─────────────────────────────────────────────────────────────────────────

  describe('POST /api/users/login', () => {
    it('should return token for valid credentials', async () => {
      const payload = createUserPayload();
      await api.post('/api/users').send(payload);

      const res = await api.post('/api/users/login').send({
        email: payload.email,
        password: payload.password,
      });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('token');
      expect(typeof res.body.data.token).toBe('string');
      expect(res.body.data).toHaveProperty('user');
      expect(res.body.data.user).toHaveProperty('id');
      expect(res.body.data.user).toHaveProperty('email');
    });

    it('should return 400 for invalid credentials', async () => {
      const payload = createUserPayload();
      await api.post('/api/users').send(payload);

      const res = await api.post('/api/users/login').send({
        email: payload.email,
        password: 'WrongPassword1!',
      });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.message.toLowerCase()).toContain('invalid email or password');
    });

    it('should return 400 for non-existent email', async () => {
      const res = await api.post('/api/users/login').send({
        email: 'nonexistent@example.com',
        password: 'SomePassword1!',
      });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.message.toLowerCase()).toContain('invalid email or password');
    });

    it('should return 400 for missing email', async () => {
      const res = await api.post('/api/users/login').send({
        password: 'SomePassword1!',
      });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should return 400 for missing password', async () => {
      const res = await api.post('/api/users/login').send({
        email: 'test@example.com',
      });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should handle login with different email case', async () => {
      const payload = createUserPayload({ email: 'Test@Example.com' });
      await api.post('/api/users').send(payload);

      const res = await api.post('/api/users/login').send({
        email: 'test@example.com',
        password: payload.password,
      });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // GET /api/users (List) - ADMIN ONLY
  // ─────────────────────────────────────────────────────────────────────────

  describe('GET /api/users (List)', () => {
    it('should return list of users for admin', async () => {
      await api.post('/api/users').send(createUserPayload());
      await api.post('/api/users').send(createUserPayload());

      const adminToken = createAdminToken();
      const res = await api.get('/api/users').set('Authorization', authHeader(adminToken));

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBe(2);
    });

    it('should return 401 for non-admin users', async () => {
      const userToken = createUserToken();

      const res = await api.get('/api/users').set('Authorization', authHeader(userToken));

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      const unAuthorizedError = res.body.error;
      expect(unAuthorizedError.message.toLowerCase()).toContain('admin');
    });

    it('should return 401 without authentication', async () => {
      const res = await api.get('/api/users');

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should return 401 with invalid token', async () => {
      const res = await api.get('/api/users').set('Authorization', 'Bearer invalid-token');
      expect(res.status).toBe(401);
    });

    it('should support pagination with limit', async () => {
      // Create 5 users
      for (let i = 0; i < 5; i++) {
        await api.post('/api/users').send(createUserPayload());
      }

      const adminToken = createAdminToken();
      const res = await api
        .get('/api/users')
        .query({ limit: 2 })
        .set('Authorization', authHeader(adminToken));

      expect(res.status).toBe(200);
      expect(res.body.data.length).toBe(2);
    });

    it('should support pagination with limit and offset', async () => {
      // Create 5 users
      for (let i = 0; i < 5; i++) {
        await api.post('/api/users').send(createUserPayload());
      }

      const adminToken = createAdminToken();
      const res = await api
        .get('/api/users')
        .query({ limit: 2, offset: 2 })
        .set('Authorization', authHeader(adminToken));

      expect(res.status).toBe(200);
      expect(res.body.data.length).toBe(2);
    });

    it('should return empty array when no users exist', async () => {
      const adminToken = createAdminToken();
      const res = await api.get('/api/users').set('Authorization', authHeader(adminToken));

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual([]);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // GET /api/users/:id - SELF OR ADMIN
  // ─────────────────────────────────────────────────────────────────────────

  describe('GET /api/users/:id', () => {
    it('should return user for admin', async () => {
      const payload = createUserPayload();
      const createRes = await api.post('/api/users').send(payload);
      const userId = createRes.body.data.id;

      const adminToken = createAdminToken();
      const res = await api
        .get(`/api/users/${userId}`)
        .set('Authorization', authHeader(adminToken));

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.id).toBe(userId);
      expect(res.body.data.email).toBe(payload.email.toLowerCase());
      expect(res.body.data).not.toHaveProperty('passwordHash');
    });

    it('should return user data when accessing own profile', async () => {
      const payload = createUserPayload();
      const createRes = await api.post('/api/users').send(payload);
      const userId = createRes.body.data.id;

      const userToken = createUserToken(userId);
      const res = await api.get(`/api/users/${userId}`).set('Authorization', authHeader(userToken));

      expect(res.status).toBe(200);
      expect(res.body.data.id).toBe(userId);
    });

    it('should return 401 when accessing another user profile', async () => {
      const payload = createUserPayload();
      const createRes = await api.post('/api/users').send(payload);
      const userId = createRes.body.data.id;

      const otherUserToken = createUserToken('00000000-0000-0000-0000-000000000001');
      const res = await api
        .get(`/api/users/${userId}`)
        .set('Authorization', authHeader(otherUserToken));

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should return 404 for non-existent user', async () => {
      const adminToken = createAdminToken();
      const fakeId = '00000000-0000-0000-0000-000000000000';

      const res = await api
        .get(`/api/users/${fakeId}`)
        .set('Authorization', authHeader(adminToken));

      expect(res.status).toBe(404);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('NOT_FOUND');
    });

    it('should return 400 for invalid UUID format', async () => {
      const adminToken = createAdminToken();

      const res = await api
        .get('/api/users/not-a-uuid')
        .set('Authorization', authHeader(adminToken));

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should return 401 without authentication', async () => {
      const payload = createUserPayload();
      const createRes = await api.post('/api/users').send(payload);
      const userId = createRes.body.data.id;

      const res = await api.get(`/api/users/${userId}`);

      expect(res.status).toBe(401);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // PATCH /api/users/:id - SELF OR ADMIN
  // ─────────────────────────────────────────────────────────────────────────

  describe('PATCH /api/users/:id', () => {
    it('should update user name as admin', async () => {
      const payload = createUserPayload();
      const createRes = await api.post('/api/users').send(payload);
      const userId = createRes.body.data.id;

      const adminToken = createAdminToken();
      const res = await api
        .patch(`/api/users/${userId}`)
        .set('Authorization', authHeader(adminToken))
        .send({ name: 'Updated Name' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.name).toBe('Updated Name');

      // Verify database state
      const dbUser = await userRepo.findById(userId);
      expect(dbUser!.name).toBe('Updated Name');
    });

    it('should allow user to update own profile', async () => {
      const payload = createUserPayload();
      const createRes = await api.post('/api/users').send(payload);
      const userId = createRes.body.data.id;

      const userToken = createUserToken(userId);
      const res = await api
        .patch(`/api/users/${userId}`)
        .set('Authorization', authHeader(userToken))
        .send({ name: 'My New Name' });

      expect(res.status).toBe(200);
      expect(res.body.data.name).toBe('My New Name');
    });

    it('should return 401 when updating another user profile', async () => {
      const payload = createUserPayload();
      const createRes = await api.post('/api/users').send(payload);
      const userId = createRes.body.data.id;

      const otherUserToken = createUserToken('00000000-0000-0000-0000-000000000001');
      const res = await api
        .patch(`/api/users/${userId}`)
        .set('Authorization', authHeader(otherUserToken))
        .send({ name: 'Hacked Name' });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should return 404 for non-existent user', async () => {
      const adminToken = createAdminToken();
      const fakeId = '00000000-0000-0000-0000-000000000000';

      const res = await api
        .patch(`/api/users/${fakeId}`)
        .set('Authorization', authHeader(adminToken))
        .send({ name: 'Test' });

      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('NOT_FOUND');
    });

    it('should return 400 for invalid update data', async () => {
      const payload = createUserPayload();
      const createRes = await api.post('/api/users').send(payload);
      const userId = createRes.body.data.id;

      const adminToken = createAdminToken();
      const res = await api
        .patch(`/api/users/${userId}`)
        .set('Authorization', authHeader(adminToken))
        .send({ email: 'not-valid-email' });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should update multiple fields at once', async () => {
      const payload = createUserPayload();
      const createRes = await api.post('/api/users').send(payload);
      const userId = createRes.body.data.id;

      const adminToken = createAdminToken();
      const res = await api
        .patch(`/api/users/${userId}`)
        .set('Authorization', authHeader(adminToken))
        .send({
          name: 'New Name',
          dateOfBirth: '1995-05-15',
        });

      expect(res.status).toBe(200);
      expect(res.body.data.name).toBe('New Name');
      expect(res.body.data.dateOfBirth).toBe('1995-05-15');
    });

    it('should return 401 without authentication', async () => {
      const payload = createUserPayload();
      const createRes = await api.post('/api/users').send(payload);
      const userId = createRes.body.data.id;

      const res = await api.patch(`/api/users/${userId}`).send({ name: 'Test' });

      expect(res.status).toBe(401);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // DELETE /api/users/:id - ADMIN ONLY
  // ─────────────────────────────────────────────────────────────────────────

  describe('DELETE /api/users/:id', () => {
    it('should delete user as admin', async () => {
      const payload = createUserPayload();
      const createRes = await api.post('/api/users').send(payload);
      const userId = createRes.body.data.id;

      const adminToken = createAdminToken();
      const res = await api
        .delete(`/api/users/${userId}`)
        .set('Authorization', authHeader(adminToken));

      expect(res.status).toBe(204);
      expect(res.body).toEqual({});

      // Verify deletion in database
      const dbUser = await userRepo.findById(userId);
      expect(dbUser).toBeNull();
    });

    it('should return 401 for non-admin user', async () => {
      const payload = createUserPayload();
      const createRes = await api.post('/api/users').send(payload);
      const userId = createRes.body.data.id;

      const userToken = createUserToken(userId);
      const res = await api
        .delete(`/api/users/${userId}`)
        .set('Authorization', authHeader(userToken));

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);

      // Verify NOT deleted
      const dbUser = await userRepo.findById(userId);
      expect(dbUser).not.toBeNull();
    });

    it('should return 404 for non-existent user', async () => {
      const adminToken = createAdminToken();
      const fakeId = '00000000-0000-0000-0000-000000000000';

      const res = await api
        .delete(`/api/users/${fakeId}`)
        .set('Authorization', authHeader(adminToken));

      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('NOT_FOUND');
    });

    it('should return 401 without authentication', async () => {
      const payload = createUserPayload();
      const createRes = await api.post('/api/users').send(payload);
      const userId = createRes.body.data.id;

      const res = await api.delete(`/api/users/${userId}`);

      expect(res.status).toBe(401);
    });

    it('should return 400 for invalid UUID format', async () => {
      const adminToken = createAdminToken();

      const res = await api
        .delete('/api/users/not-a-uuid')
        .set('Authorization', authHeader(adminToken));

      expect(res.status).toBe(400);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // ERROR HANDLING & EDGE CASES
  // ─────────────────────────────────────────────────────────────────────────

  describe('Error Handling & Edge Cases', () => {
    it('should return 404 for unknown routes', async () => {
      const res = await api.get('/api/unknown-route');

      expect(res.status).toBe(404);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('NOT_FOUND');
    });

    it('should include request ID in error responses', async () => {
      const res = await api.get('/api/unknown-route');

      expect(res.body).toHaveProperty('requestId');
      expect(res.headers).toHaveProperty('x-request-id');
      expect(typeof res.body.requestId).toBe('string');
    });

    it('should handle malformed JSON body', async () => {
      const res = await api
        .post('/api/users')
        .set('Content-Type', 'application/json')
        .send('{ invalid json }');

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should handle missing Content-Type header', async () => {
      const payload = createUserPayload();

      const res = await api.post('/api/users').send(payload);

      // Should still work because supertest sets it automatically
      expect(res.status).toBe(201);
    });

    it('should handle extremely long field values', async () => {
      const payload = createUserPayload({
        name: 'A'.repeat(1000),
      });

      const res = await api.post('/api/users').send(payload);

      // Should either accept or reject gracefully
      expect([200, 201, 400]).toContain(res.status);
    });

    it('should handle special characters in email', async () => {
      const payload = createUserPayload({
        email: 'user+tag@example.com',
      });

      const res = await api.post('/api/users').send(payload);

      expect(res.status).toBe(201);
    });

    it('should reject SQL injection attempts in email', async () => {
      const payload = createUserPayload({
        email: "admin'--@example.com",
      });

      const res = await api.post('/api/users').send(payload);

      // Should either validate or safely handle
      expect([400, 201]).toContain(res.status);
      if (res.status === 201) {
        // Ensure it's stored safely
        const dbUser = await userRepo.findByEmail(payload.email);
        expect(dbUser?.email).toBe(payload.email.toLowerCase());
      }
    });

    it('should handle concurrent registrations with same email', async () => {
      const payload = createUserPayload();

      const [res1, res2] = await Promise.all([
        api.post('/api/users').send(payload),
        api.post('/api/users').send(payload),
      ]);

      // One should succeed, one should fail
      const statuses = [res1.status, res2.status].sort();
      expect(statuses).toEqual([201, 409]);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // RESPONSE ENVELOPE STRUCTURE
  // ─────────────────────────────────────────────────────────────────────────

  describe('Response Envelope Structure', () => {
    it('should have consistent success response structure', async () => {
      const payload = createUserPayload();
      const res = await api.post('/api/users').send(payload);

      expect(res.body).toHaveProperty('success', true);
      expect(res.body).toHaveProperty('data');
      expect(res.body).toHaveProperty('requestId');
      expect(res.body).not.toHaveProperty('error');
    });

    it('should have consistent error response structure', async () => {
      const res = await api.post('/api/users').send({});

      expect(res.body).toHaveProperty('success', false);
      expect(res.body).toHaveProperty('error');
      expect(res.body.error).toHaveProperty('code');
      expect(res.body.error).toHaveProperty('message');
      expect(res.body).toHaveProperty('requestId');
      expect(res.body).not.toHaveProperty('data');
    });

    it('should include validation details in 400 errors', async () => {
      const res = await api.post('/api/users').send({ email: 'invalid' });

      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(res.body.error).toHaveProperty('details');
      expect(Array.isArray(res.body.error.details)).toBe(true);
    });

    it('should set correct Content-Type header', async () => {
      const res = await api.get('/api/users');

      expect(res.headers['content-type']).toMatch(/application\/json/);
    });
  });
});
