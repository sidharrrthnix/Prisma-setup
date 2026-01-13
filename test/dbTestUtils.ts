import { PrismaClient } from '@prisma/client';
import { afterAll, beforeAll, beforeEach } from 'vitest';

// Create a singleton test Prisma instance
const testPrisma = new PrismaClient({
  log: ['error'],
});

export function useTestDb() {
  beforeAll(async () => {
    await testPrisma.$connect();
  });

  beforeEach(async () => {
    // Clean up all tables
    await testPrisma.user.deleteMany();
  });

  afterAll(async () => {
    await testPrisma.$disconnect();
  });

  return testPrisma;
}
