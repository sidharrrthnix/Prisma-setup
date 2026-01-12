import jwt from 'jsonwebtoken';
import { env } from './env.js';

export interface TokenPayload {
  userId: string;
  email: string;
  role: 'user' | 'admin';
}

export function signToken(payload: TokenPayload): string {
  return jwt.sign(payload, env.JWT_SECRET, { expiresIn: '1h' });
}

export function verifyToken(token: string): TokenPayload {
  return jwt.verify(token, env.JWT_SECRET) as TokenPayload;
}
