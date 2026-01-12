import type { NextFunction, Request, Response } from 'express';
import { ZodError, ZodTypeAny } from 'zod';
import { zodToValidationError } from '../errors/zod';

export function validateBody<T extends ZodTypeAny>(schema: T) {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      res.locals.body = schema.parse(req.body);
      next();
    } catch (e) {
      if (e instanceof ZodError) return next(zodToValidationError(e));
      next(e);
    }
  };
}
