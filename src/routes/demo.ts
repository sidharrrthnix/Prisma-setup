import { Router } from 'express';
import {
  ConflictError,
  ForbiddenError,
  NotAuthorizedError,
  NotFoundError,
  ValidationError,
} from '../errors/httpErrors';
import { asyncHandler } from '../lib/asyncHandler';
import { sendSuccess } from '../lib/envelope';

export function demoRouter(): Router {
  const router = Router();

  router.get('/ok', (_req, res) => sendSuccess(res, { message: 'ok' }));

  router.get('/unauthorized', () => {
    throw new NotAuthorizedError('Missing or invalid auth token');
  });

  router.get('/forbidden', () => {
    throw new ForbiddenError('You do not have access to this resource');
  });

  router.get('/conflict', () => {
    throw new ConflictError('Resource already exists');
  });

  router.get('/not-found', () => {
    throw new NotFoundError('The requested resource was not found');
  });

  router.get('/validation', () => {
    throw new ValidationError('Validation Failed', [
      { path: 'field', message: 'field is required' },
    ]);
  });

  router.get(
    '/async-forbidden',
    asyncHandler(async () => {
      await Promise.resolve();
      throw new ForbiddenError('Async forbidden error');
    }),
  );

  router.get(
    '/boom',
    asyncHandler(async () => {
      await Promise.resolve();
      throw new Error('kaboom - should never be exposed to clients');
    }),
  );

  return router;
}
