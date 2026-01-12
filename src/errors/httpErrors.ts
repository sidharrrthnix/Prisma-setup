import { AppError, ErrorDetail } from './AppError';

export class ValidationError extends AppError {
  constructor(message = 'Validation Error', details?: ErrorDetail[]) {
    super({ message, code: 'VALIDATION_ERROR', status: 400, details });
  }
}

export class NotAuthorizedError extends AppError {
  constructor(message = 'Not Authorized', code = 'UNAUTHORIZED') {
    super({ message, code, status: 401 });
  }
}

export class ConflictError extends AppError {
  constructor(message = 'Conflict', code = 'CONFLICT') {
    super({ message, code, status: 409 });
  }
}

export class NotFoundError extends AppError {
  constructor(message = 'Not Found', code = 'NOT_FOUND') {
    super({ message, code, status: 404 });
  }
}

export class ForbiddenError extends AppError {
  constructor(message = 'Forbidden', code = 'FORBIDDEN') {
    super({ message, code, status: 403 });
  }
}

export class BadRequestError extends AppError {
  constructor(message = 'Bad Request', code = 'BAD_REQUEST') {
    super({ message, code, status: 400 });
  }
}

export class ServiceUnavailableError extends AppError {
  constructor(message = 'Service Unavailable', code = 'SERVICE_UNAVAILABLE') {
    super({ message, code, status: 503 });
  }
}
