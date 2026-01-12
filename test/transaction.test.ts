import { randomUUID } from 'crypto';
import { createPool } from '../src/db/pool';
import { query } from '../src/db/query';
import { withTransaction } from '../src/db/transaction';
import { useTestDb } from './dbTestUtils';

describe('withTransaction', () => {
  const pool = useTestDb();
  it('commits on success', async () => {
    const result = await withTransaction(pool, async (tx) => {
      await withTransaction(pool, async (tx) => {
        await query(
          tx,
          'INSERT INTO users (id, email, password_hash, name, date_of_birth) VALUES ($1, $2, $3, $4, $5) RETURNING id',
          [randomUUID(), 'test@example.com', 'password', 'Test User', '1990-01-01'],
        );
        const res = await query(tx, 'SELECT * FROM users WHERE email=$1', ['test@example.com']);
        expect(res.rows.length).toBe(1);
        expect(res.rows[0]?.email).toBe('test@example.com');
      });
    });
  });
  it('rolls back on error', async () => {
    await expect(
      withTransaction(pool, async (tx) => {
        await query(
          tx,
          'INSERT INTO users (id, email, password_hash, name, date_of_birth) VALUES ($1, $2, $3, $4, $5) RETURNING id',
          [randomUUID(), 'test@example.com', 'password', 'Test User', '1990-01-01'],
        );
        throw new Error('test error');
      }),
    ).rejects.toThrow('test error');

    const res = await query(pool, 'SELECT * FROM users WHERE email=$1', ['test@example.com']);
    expect(res.rows.length).toBe(0);
  });
  it('connection pool behavior: waits when max connections are used', async () => {
    // separate small pool just for this test
    const connectionString = process.env.DATABASE_URL!;
    const tiny = createPool({ connectionString, max: 1 });

    const c1 = await tiny.connect(); // holds the only slot
    const p2 = tiny.connect(); // should wait

    // give event loop a tick so waitingCount updates
    await new Promise((r) => setTimeout(r, 20));

    expect(tiny.waitingCount).toBeGreaterThanOrEqual(1);

    c1.release();
    const c2 = await p2;
    c2.release();

    await tiny.end();
  });
});
