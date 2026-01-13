import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function setupTestDatabase(): Promise<void> {
  await prisma.$connect();
}

export async function teardownTestDatabase(): Promise<void> {
  await prisma.user.deleteMany();
}

export async function cleanupDatabase(): Promise<void> {
  await prisma.user.deleteMany();
}

export async function closeDatabase(): Promise<void> {
  await prisma.$disconnect();
}

export function getTestPrisma(): PrismaClient {
  return prisma;
}
