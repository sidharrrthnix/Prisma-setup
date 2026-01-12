import { PrismaClient } from '@prisma/client';
import express from 'express';
import { getPrisma } from './db/prisma';
import { sendSuccess } from './lib/envelope';
import { errorHandler } from './middleware/errorHandler';
import { notFound } from './middleware/notFound';
import { requestIdMiddleware } from './middleware/requestId';
import { demoRouter } from './routes/demo';
import { usersRouter } from './routes/users';

export function createApp(opts?: { prisma?: PrismaClient }) {
  const prisma = opts?.prisma ?? getPrisma();
  const app = express();

  app.disable('x-powered-by');
  app.use(requestIdMiddleware);
  app.use(express.json());
  app.get('/health', (_req, res) => sendSuccess(res, { status: 'ok' }));

  app.use('/api/users', usersRouter({ prisma }));
  app.use('/api/demo', demoRouter());

  app.use(notFound);
  app.use(errorHandler);
  return app;
}

export const app = createApp();
