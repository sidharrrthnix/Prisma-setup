import { ErrorRequestHandler } from 'express';
import { ZodError } from 'zod';
import { AppError } from '../errors/AppError';
import { zodToValidationError } from '../errors/zod';
import { ErrorEnvelope } from '../lib/envelope';

export const errorHandler: ErrorRequestHandler = (err, req, res, _next) => {
  const requestId = req.requestId ?? res.locals.requestId ?? 'unknown';

  const normalized =
    err instanceof ZodError ? zodToValidationError(err) : err instanceof AppError ? err : null;

  const status = normalized?.status ?? 500;
  const code = normalized?.code ?? 'INTERNAL_ERROR';
  const message = normalized ? normalized.message : 'Internal Server Error';

  const body: ErrorEnvelope = {
    success: false,
    requestId,
    error: {
      code,
      message,
      ...(normalized?.details ? { details: normalized.details } : {}),
    },
  };
  res.setHeader('X-REQUEST-ID', requestId);

  res.status(status).json(body);
};
