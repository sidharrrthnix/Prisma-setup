export interface ErrorDetail {
  path: string;
  message: string;
}

export class AppError extends Error {
  code: string;
  status: number;
  details?: ErrorDetail[];

  constructor(opts: { message: string; code: string; status: number; details?: ErrorDetail[] }) {
    super(opts.message);
    this.code = opts.code;
    this.status = opts.status;
    this.details = opts.details;

    Error.captureStackTrace(this, new.target);
  }
}
