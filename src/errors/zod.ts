import { ZodError } from 'zod';
import type { ErrorDetail } from './AppError';
import { ValidationError } from './httpErrors';

export function zodToValidationError(err: ZodError): ValidationError {
  const details: ErrorDetail[] = err.issues.map((issue) => ({
    path: issue.path.join('.'),
    message: issue.message,
  }));

  return new ValidationError('Validation Failed', details);
}
