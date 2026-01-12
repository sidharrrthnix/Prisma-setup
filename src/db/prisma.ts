import { Prisma, PrismaClient } from '@prisma/client';
import {
  BadRequestError,
  ConflictError,
  NotFoundError,
  ServiceUnavailableError,
} from '../errors/httpErrors';
import { env } from '../lib/env';

// Singleton pattern
const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

function createPrismaClient(): PrismaClient {
  return new PrismaClient({
    log: env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error'],
  });
}

export const prisma = globalForPrisma.prisma ?? createPrismaClient();

if (env.NODE_ENV !== 'production') {
  globalForPrisma.prisma = prisma;
}

export function getPrisma(): PrismaClient {
  return prisma;
}

// Connection with retry logic
export async function connectWithRetry(): Promise<void> {
  const maxRetries = env.DB_CONNECT_RETRIES;
  const baseDelay = env.DB_CONNECT_RETRY_DELAY;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      await prisma.$connect();
      return;
    } catch (err) {
      const isLastAttempt = attempt === maxRetries;
      if (isLastAttempt) {
        throw err;
      }

      console.warn(`Database connection attempt ${attempt + 1} failed, retrying...`);
      await sleep(baseDelay * Math.pow(2, attempt));
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Error mapping
export function mapPrismaError(err: unknown): Error {
  if (err instanceof Prisma.PrismaClientKnownRequestError) {
    switch (err.code) {
      case 'P2002': // Unique constraint violation
        const field = (err.meta?.target as string[])?.join(', ') || 'field';
        return new ConflictError(`${field} already exists`);

      case 'P2003': // Foreign key constraint violation
        return new BadRequestError('Invalid reference (foreign key violation)');

      case 'P2025': // Record not found
        return new NotFoundError('Record not found');

      case 'P2014': // Required relation violation
        return new BadRequestError('Required relation not satisfied');

      default:
        return new ServiceUnavailableError('Database error');
    }
  }

  if (err instanceof Prisma.PrismaClientUnknownRequestError) {
    return new ServiceUnavailableError('Database error');
  }

  if (err instanceof Prisma.PrismaClientInitializationError) {
    return new ServiceUnavailableError('Database connection failed');
  }

  return err as Error;
}

// Graceful shutdown
process.on('beforeExit', async () => {
  await prisma.$disconnect();
});
