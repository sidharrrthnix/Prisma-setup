import { RequestHandler } from 'express';
import { NotAuthorizedError } from '../errors/httpErrors';
import { TokenPayload, verifyToken } from '../lib/jwt';

declare global {
  namespace Express {
    interface Request {
      user?: TokenPayload;
    }
  }
}

export const authenticate: RequestHandler = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    return next(new NotAuthorizedError('Missing or invalid Authorization header'));
  }

  const token = authHeader.slice(7);

  try {
    const payload = verifyToken(token);
    req.user = payload;
    next();
  } catch (err) {
    return next(new NotAuthorizedError('Invalid or expired token'));
  }
};

export const requireAdmin: RequestHandler = (req, res, next) => {
  if (!req.user) {
    return next(new NotAuthorizedError('User not authenticated'));
  }
  if (req.user.role !== 'admin') {
    return next(new NotAuthorizedError('Admin privileges required'));
  }
  next();
};

export const requireSelfOrAdmin: RequestHandler = (req, res, next) => {
  if (!req.user) {
    return next(new NotAuthorizedError('User not authenticated'));
  }
  const userId = req.params.userId;
  const isSelf = req.user.userId === userId;
  if (!isSelf && req.user.role !== 'admin') {
    return next(new NotAuthorizedError('Access denied'));
  }
  next();
};
