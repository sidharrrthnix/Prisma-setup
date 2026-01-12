export {};

declare global {
  namespace Express {
    interface Request {
      requestId: string;
    }
    interface Locals {
      requestId: string;
      body?: unknown;
    }
  }
}
