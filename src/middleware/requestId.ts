import { randomUUID } from 'crypto';
import { RequestHandler } from 'express';

export const REQUEST_ID_HEADER = 'x-request-id';

export const requestIdMiddleware: RequestHandler = (req, res, next) => {
  const incoming = req.header(REQUEST_ID_HEADER);

  const requestId =
    typeof incoming === 'string' && incoming.trim().length > 0 ? incoming.trim() : randomUUID();

  req.requestId = requestId;
  res.locals.requestId = requestId;

  res.setHeader('X-REQUEST-ID', requestId);

  next();
};
