import { PrismaClient } from '@prisma/client';
import { Router } from 'express';
import { BadRequestError, NotFoundError } from '../errors/httpErrors';
import { asyncHandler } from '../lib/asyncHandler';
import { sendSuccess } from '../lib/envelope';
import { signToken } from '../lib/jwt';
import { hashPassword, verifyPassword } from '../lib/password';
import { authenticate, requireAdmin } from '../middleware/auth';
import { validateBody } from '../middleware/validate';
import { transferCredits } from '../repositories/transferCredits';
import { UserRepository } from '../repositories/UserRepository';
import {
  CreateUserInput,
  createUserSchema,
  loginSchema,
  TransferCreditsInput,
  transferCreditsSchema,
  UpdateUserInput,
  updateUserSchema,
} from '../validation/user.schema';

export function usersRouter(opts: { prisma: PrismaClient }): Router {
  const router = Router();
  const { prisma } = opts;
  const repo = new UserRepository(prisma);

  router.post(
    '/',
    validateBody(createUserSchema),
    asyncHandler(async (req, res, next) => {
      const { password, ...userData } = res.locals.body as CreateUserInput;

      const passwordHash = await hashPassword(password);

      const user = await repo.create({ ...userData, passwordHash });

      return sendSuccess(res, user, 201);
    }),
  );

  router.post(
    '/login',
    validateBody(loginSchema),
    asyncHandler(async (req, res, next) => {
      const { email, password } = res.locals.body as { email: string; password: string };
      const user = await repo.findByEmail(email);
      if (!user) {
        return next(new BadRequestError('Invalid email or password'));
      }
      const valid = await verifyPassword(password, user.passwordHash);
      if (!valid) {
        return next(new BadRequestError('Invalid email or password'));
      }
      const token = signToken({
        userId: user.id,
        email: user.email,
        role: (user as any).role ?? 'user',
      });
      const { passwordHash: _, ...userData } = user;
      return sendSuccess(res, { token, user: userData });
    }),
  );

  router.get(
    '/',
    authenticate,
    requireAdmin,
    asyncHandler(async (req, res, next) => {
      const users = await repo.findAll();
      return sendSuccess(res, users);
    }),
  );

  router.post(
    '/transfer-credits',
    validateBody(transferCreditsSchema),
    asyncHandler(async (req, res, next) => {
      const body = res.locals.body as TransferCreditsInput;
      const result = await transferCredits(prisma, body);
      return sendSuccess(res, result);
    }),
  );

  router.get(
    '/:id',
    asyncHandler(async (req, res, next) => {
      const { id } = req.params;
      if (!id) {
        return next(new BadRequestError('User ID is required'));
      }
      const user = await repo.findById(id);
      if (!user) {
        return next(new NotFoundError('User not found'));
      }
      return sendSuccess(res, user);
    }),
  );

  router.patch(
    '/:id',
    validateBody(updateUserSchema),
    asyncHandler(async (req, res, next) => {
      const { id } = req.params;
      if (!id) {
        return next(new BadRequestError('User ID is required'));
      }
      const body = res.locals.body as UpdateUserInput;
      const user = await repo.update(id, body);
      if (!user) {
        return next(new NotFoundError('User not found'));
      }
      return sendSuccess(res, user);
    }),
  );

  router.delete(
    '/:id',
    asyncHandler(async (req, res, next) => {
      const { id } = req.params;
      if (!id) {
        return next(new BadRequestError('User ID is required'));
      }
      const deleted = await repo.delete(id);
      if (!deleted) {
        return next(new NotFoundError('User not found'));
      }
      return sendSuccess(res, null, 204);
    }),
  );

  return router;
}
