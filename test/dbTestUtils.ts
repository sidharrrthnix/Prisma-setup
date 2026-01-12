import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach } from 'vitest';
import { ensureSchema } from '../src/db/schema';

export function useTestDb() {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error('DATABASE_URL is not set');
  }

  const pool = new Pool({
    connectionString,
    max: 3,
    ssl: false,
    allowExitOnIdle: true,
  });

  pool.on('error', (err) => {
    console.error('[test db] pool error', err);
  });

  beforeAll(async () => {
    await ensureSchema(pool);
  });

  beforeEach(async () => {
    await pool.query(`TRUNCATE TABLE users CASCADE`);
  });

  afterAll(async () => {
    await pool.end();
  });

  return pool;
}
