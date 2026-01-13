import { ConflictError, NotFoundError } from '../src/errors/httpErrors';
import { UserRepository } from '../src/repositories/UserRepository';
import { useTestDb } from './dbTestUtils';

describe('UserRepository CRUD', () => {
  const prisma = useTestDb();
  const repo = new UserRepository(prisma);

  it('create + findById', async () => {
    const created = await repo.create({
      email: 'john@example.com',
      passwordHash: 'hash',
      name: 'John',
      dateOfBirth: '1990-01-01',
    });
    const found = await repo.findById(created.id);
    expect(found?.email).toEqual(created.email);
    expect(found?.name).toEqual(created.name);
    expect(found?.dateOfBirth).toEqual(created.dateOfBirth);
    expect(found?.credits).toEqual(created.credits);
  });

  it('create + findByEmail (case-insensitive)', async () => {
    const created = await repo.create({
      email: 'john@example.com',
      passwordHash: 'hash',
      name: 'John',
      dateOfBirth: '1990-01-01',
    });
    const found = await repo.findByEmail('JOHN@EXAMPLE.COM');
    expect(found).not.toBeNull();
    expect(found?.email).toEqual(created.email);
  });

  it('update', async () => {
    const created = await repo.create({
      email: 'john@example.com',
      passwordHash: 'hash',
      name: 'John',
      dateOfBirth: '1990-01-01',
    });
    const updated = await repo.update(created.id, { name: 'A2' });
    expect(updated?.name).toEqual('A2');
  });

  it('delete', async () => {
    const created = await repo.create({
      email: 'john@example.com',
      passwordHash: 'hash',
      name: 'John',
      dateOfBirth: '1990-01-01',
    });
    const deleted = await repo.delete(created.id);
    expect(deleted).toBe(true);

    const found = await repo.findById(created.id);
    expect(found).toBeNull();
  });

  it('delete non-existent -> NotFoundError', async () => {
    const id = '00000000-0000-0000-0000-000000000099';
    await expect(repo.delete(id)).rejects.toBeInstanceOf(NotFoundError);
    await expect(repo.delete(id)).rejects.toThrow();
  });

  it('unique constraint violation -> ConflictError', async () => {
    await repo.create({
      email: 'john@example.com',
      passwordHash: 'hash',
      name: 'John',
      dateOfBirth: '1990-01-01',
    });
    await expect(
      repo.create({
        email: 'john@example.com',
        passwordHash: 'hash',
        name: 'John',
        dateOfBirth: '1990-01-01',
      }),
    ).rejects.toBeInstanceOf(ConflictError);
  });
});
