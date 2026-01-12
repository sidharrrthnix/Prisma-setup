import { RequestHandler } from 'express';
import { NotFoundError } from '../errors/httpErrors';

export const notFound: RequestHandler = (_req, _res, next) => {
  next(new NotFoundError('Requested Page is Not Found'));
};
