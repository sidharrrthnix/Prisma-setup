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
