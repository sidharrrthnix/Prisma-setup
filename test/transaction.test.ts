import { randomUUID } from 'crypto';
import { describe, expect, it } from 'vitest';
import { withTransaction } from '../src/db/transaction';
import { useTestDb } from './dbTestUtils';

describe('withTransaction', () => {
  const prisma = useTestDb();

  it('commits on success', async () => {
    await withTransaction(prisma, async (tx) => {
      await tx.user.create({
        data: {
          id: randomUUID(),
          email: 'test@example.com',
          passwordHash: 'password',
          name: 'Test User',
          dateOfBirth: '1990-01-01',
        },
      });
    });

    const user = await prisma.user.findUnique({
      where: { email: 'test@example.com' },
    });

    expect(user).not.toBeNull();
    expect(user?.email).toBe('test@example.com');
  });

  it('rolls back on error', async () => {
    await expect(
      withTransaction(prisma, async (tx) => {
        await tx.user.create({
          data: {
            id: randomUUID(),
            email: 'rollback@example.com',
            passwordHash: 'password',
            name: 'Test User',
            dateOfBirth: '1990-01-01',
          },
        });
        throw new Error('test error');
      }),
    ).rejects.toThrow('test error');

    const user = await prisma.user.findUnique({
      where: { email: 'rollback@example.com' },
    });
    expect(user).toBeNull();
  });

  it('handles isolation levels', async () => {
    await withTransaction(
      prisma,
      async (tx) => {
        await tx.user.create({
          data: {
            id: randomUUID(),
            email: 'isolation@example.com',
            passwordHash: 'password',
            name: 'Test User',
            dateOfBirth: '1990-01-01',
          },
        });
        await tx.user.create({
          data: {
            id: randomUUID(),
            email: 'isolation@example.com',
            passwordHash: 'password',
            name: 'Test User',
            dateOfBirth: '1990-01-01',
          },
        });
      },
      { isolationLevel: 'Serializable' },
    );

    const user = await prisma.user.findUnique({
      where: { email: 'isolation@example.com' },
    });
    expect(user).not.toBeNull();
    expect(user?.email).toBe('isolation@example.com');
  });
});
