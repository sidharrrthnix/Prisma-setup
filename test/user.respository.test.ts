import { BadRequestError, ConflictError } from '../src/errors/httpErrors';
import { UserRepository } from '../src/repositories/UserRepository';
import { useTestDb } from './dbTestUtils';

describe('UserRepository CRUD', () => {
  const pool = useTestDb();
  const repo = new UserRepository(pool);

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
    expect(found?.createdAt).toEqual(created.createdAt);
    expect(found?.updatedAt).toEqual(created.updatedAt);
  });

  it('create + findByEmail', async () => {
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
  });
  it('delete non-existent', async () => {
    await expect(repo.delete('00000000-0000-0000-0000-000000000099')).rejects.toBeInstanceOf(
      BadRequestError,
    );
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
