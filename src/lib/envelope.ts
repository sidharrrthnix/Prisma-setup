import type { Response } from 'express';
import { ErrorDetail } from '../errors/AppError';

export type SuccessEnvelope<T> = {
  success: true;
  requestId: string;
  data: T;
};

export type ErrorEnvelope = {
  success: false;
  requestId: string;
  error: {
    code: string;
    message: string;
    details?: ErrorDetail[];
  };
};

export type Envelope<T> = SuccessEnvelope<T> | ErrorEnvelope;

export function sendSuccess<T>(res: Response, data: T, status = 200): Response {
  const requestId = res.locals.requestId;
  const body: SuccessEnvelope<T> = { success: true, requestId, data };
  return res.status(status).json(body);
}
