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

