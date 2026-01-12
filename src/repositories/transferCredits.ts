import { PrismaClient } from '@prisma/client';
import { withTransaction } from '../db/transaction';
import { BadRequestError, NotFoundError } from '../errors/httpErrors';
import { User } from './user.types';
import { UserRepository } from './UserRepository';

export async function transferCredits(
  prisma: PrismaClient,
  params: { fromUserId: string; toUserId: string; amount: number },
): Promise<{ from: User; to: User }> {
  const { fromUserId, toUserId, amount } = params;

  if (fromUserId === toUserId) {
    throw new BadRequestError('From and to user IDs cannot be the same');
  }
  if (!Number.isInteger(amount) || amount <= 0) {
    throw new BadRequestError('Amount must be a positive integer');
  }
  const repo = new UserRepository(prisma);
  return withTransaction(prisma, async (tx) => {
    const ids = [fromUserId, toUserId].sort();

    const locked = await tx.user.findMany({
      where: { id: { in: ids } },
      for: { update: { mode: 'forUpdate' } },
    });

    if (locked.length !== 2) {
      const found = new Set(locked.map((u: User) => u.id));
      if (!found.has(fromUserId)) {
        throw new NotFoundError(`User ${fromUserId} not found`);
      }
      if (!found.has(toUserId)) {
        throw new NotFoundError(`User ${toUserId} not found`);
      }
      throw new NotFoundError('Users not found');
    }

    const [from, to] = locked;
    if (from!.credits < amount) {
      throw new BadRequestError('Insufficient credits');
    }

    await tx.user.update({
      where: { id: fromUserId },
      data: { credits: { decrement: amount } },
    });
    await tx.user.update({
      where: { id: toUserId },
      data: { credits: { increment: amount } },
    });

    const fromAfter = await repo.findById(fromUserId);
    const toAfter = await repo.findById(toUserId);
    if (!fromAfter || !toAfter) {
      throw new NotFoundError('Users not found');
    }

    return { from: fromAfter, to: toAfter };
  });
}
