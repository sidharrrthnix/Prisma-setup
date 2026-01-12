import { Prisma, PrismaClient } from '@prisma/client';

export type IsolationLevel = Prisma.TransactionIsolationLevel;

export type TransactionOptions = {
  isolationLevel?: IsolationLevel;
  maxWait?: number;
  timeout?: number;
};

export async function withTransaction<T>(
  prisma: PrismaClient,
  fn: (tx: Prisma.TransactionClient) => Promise<T>,
  opts: TransactionOptions = {},
): Promise<T> {
  try {
    return await prisma.$transaction(fn, {
      isolationLevel: opts.isolationLevel,
      maxWait: opts.maxWait ?? 5000,
      timeout: opts.timeout ?? 10000,
    });
  } catch (e) {
    throw e;
  }
}
