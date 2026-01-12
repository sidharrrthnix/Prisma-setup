// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/index.ts
// ═══════════════════════════════════════════════════════════════════════════
import { app } from './server';
import { env } from './lib/env';
import { pool } from './db/pool';
import { ensureSchema } from './db/schema';

const PORT = env.PORT || 3000;

async function start() {
  try {
    // Ensure database schema exists
    await ensureSchema(pool);
    console.log('✓ Database schema ensured');

    // Start server
    app.listen(PORT, () => {
      console.log(`✓ Server running on port ${PORT}`);
      console.log(`✓ Environment: ${env.NODE_ENV}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, closing server...');
  await pool.end();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, closing server...');
  await pool.end();
  process.exit(0);
});

start();


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/server.ts
// ═══════════════════════════════════════════════════════════════════════════
import express from 'express';
import { requestId } from './middleware/requestId';
import { errorHandler } from './middleware/errorHandler';
import { notFound } from './middleware/notFound';
import usersRouter from './routes/users';
import demoRouter from './routes/demo';

export const app = express();

// Middleware
app.use(express.json());
app.use(requestId);

// Routes
app.use('/api/users', usersRouter);
app.use('/api/demo', demoRouter);

// Error handling (must be last)
app.use(notFound);
app.use(errorHandler);


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/db/pool.ts
// ═══════════════════════════════════════════════════════════════════════════
import { Pool, PoolConfig } from 'pg';
import { env } from '../lib/env';

const base: PoolConfig = {
  host: env.DB_HOST,
  port: env.DB_PORT,
  database: env.DB_NAME,
  user: env.DB_USER,
  password: env.DB_PASSWORD,
  max: env.DB_POOL_MAX,
  idleTimeoutMillis: env.DB_IDLE_TIMEOUT,
  connectionTimeoutMillis: env.DB_CONNECTION_TIMEOUT,
};

export const pool = new Pool(base);

// Log pool errors
pool.on('error', (err) => {
  console.error('Unexpected database pool error:', err);
});

// Log pool connection
pool.on('connect', () => {
  console.log('New database connection established');
});


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/db/query.ts
// ═══════════════════════════════════════════════════════════════════════════
import { Pool, PoolClient, QueryResult } from 'pg';
import { AppError } from '../errors/AppError';
import { BadRequestError, ConflictError } from '../errors/httpErrors';

export type Queryable = Pool | PoolClient;

export async function query<T = any>(
  db: Queryable,
  text: string,
  params?: any[],
): Promise<QueryResult<T>> {
  const maxRetries = 3;
  const baseDelay = 100;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await db.query<T>(text, params);
    } catch (err) {
      // Check if error is retryable (connection issues)
      if (isTransientError(err) && attempt < maxRetries) {
        const delay = baseDelay * Math.pow(2, attempt - 1);
        console.warn(`Query attempt ${attempt} failed, retrying in ${delay}ms...`);
        await sleep(delay);
        continue;
      }

      // Map database errors to application errors
      throw mapDbError(err);
    }
  }

  throw new AppError('Query failed after retries');
}

function isTransientError(err: unknown): boolean {
  if (typeof err !== 'object' || err === null) return false;

  const code = (err as any).code;
  const transientCodes = [
    'ECONNREFUSED',
    'ECONNRESET',
    'ETIMEDOUT',
    'ENOTFOUND',
    '57P01', // admin_shutdown
    '57P02', // crash_shutdown
    '57P03', // cannot_connect_now
  ];

  return transientCodes.includes(code);
}

function mapDbError(err: unknown): Error {
  if (!(err instanceof Error)) {
    return new AppError('Unknown database error');
  }

  const pgError = err as any;
  const code = pgError.code;

  switch (code) {
    case '23505': // unique_violation
      return withCause(
        new ConflictError('Unique constraint violation: Resource already exists'),
        err,
      );

    case '23503': // foreign_key_violation
      return withCause(new BadRequestError('Foreign key constraint violation'), err);

    case '23502': // not_null_violation
      return withCause(new BadRequestError('Required field is missing'), err);

    case '22P02': // invalid_text_representation (e.g., invalid UUID)
      return withCause(new BadRequestError('Invalid data format'), err);

    case '42P01': // undefined_table
      return withCause(new AppError('Database table does not exist'), err);

    default:
      // For unknown errors, preserve original error
      return err;
  }
}

function withCause(error: Error, cause: Error): Error {
  (error as any).cause = cause;
  return error;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/db/schema.ts
// ═══════════════════════════════════════════════════════════════════════════
import { Pool } from 'pg';

export async function ensureSchema(pool: Pool): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      name VARCHAR(255) NOT NULL,
      date_of_birth DATE,
      credits INTEGER NOT NULL DEFAULT 0,
      role VARCHAR(50) NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_users_email ON users(LOWER(email));
    CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
  `);
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/db/transaction.ts
// ═══════════════════════════════════════════════════════════════════════════
import { Pool, PoolClient } from 'pg';

export type IsolationLevel =
  | 'READ UNCOMMITTED'
  | 'READ COMMITTED'
  | 'REPEATABLE READ'
  | 'SERIALIZABLE';

export interface TransactionOptions {
  isolationLevel?: IsolationLevel;
  retries?: number;
}

export async function withTransaction<T>(
  pool: Pool,
  fn: (client: PoolClient) => Promise<T>,
  options: TransactionOptions = {},
): Promise<T> {
  const { isolationLevel = 'READ COMMITTED', retries = 3 } = options;

  for (let attempt = 1; attempt <= retries; attempt++) {
    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      if (isolationLevel !== 'READ COMMITTED') {
        await client.query(`SET TRANSACTION ISOLATION LEVEL ${isolationLevel}`);
      }

      const result = await fn(client);

      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK');

      // Check if error is retryable (serialization failure, deadlock)
      if (isRetryableDbError(err) && attempt < retries) {
        console.warn(`Transaction attempt ${attempt} failed, retrying...`);
        continue;
      }

      throw err;
    } finally {
      client.release();
    }
  }

  throw new Error('Transaction failed after retries');
}

function isRetryableDbError(err: unknown): boolean {
  if (typeof err !== 'object' || err === null) return false;

  const code = (err as any).code;
  return code === '40001' || code === '40P01'; // serialization_failure, deadlock_detected
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/errors/AppError.ts
// ═══════════════════════════════════════════════════════════════════════════
export class AppError extends Error {
  public readonly statusCode: number;
  public readonly code: string;
  public readonly isOperational: boolean;

  constructor(message: string, statusCode = 500, code = 'INTERNAL_ERROR') {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/errors/httpErrors.ts
// ═══════════════════════════════════════════════════════════════════════════
import { AppError } from './AppError';

export class BadRequestError extends AppError {
  constructor(message = 'Bad Request') {
    super(message, 400, 'BAD_REQUEST');
  }
}

export class UnauthorizedError extends AppError {
  constructor(message = 'Unauthorized') {
    super(message, 401, 'UNAUTHORIZED');
  }
}

export class ForbiddenError extends AppError {
  constructor(message = 'Forbidden') {
    super(message, 403, 'FORBIDDEN');
  }
}

export class NotFoundError extends AppError {
  constructor(message = 'Resource not found') {
    super(message, 404, 'NOT_FOUND');
  }
}

export class ConflictError extends AppError {
  constructor(message = 'Resource already exists') {
    super(message, 409, 'CONFLICT');
  }
}

export class InternalServerError extends AppError {
  constructor(message = 'Internal Server Error') {
    super(message, 500, 'INTERNAL_ERROR');
  }
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/errors/zod.ts
// ═══════════════════════════════════════════════════════════════════════════
import { ZodError } from 'zod';
import { AppError } from './AppError';

export interface ValidationErrorDetail {
  path: string;
  message: string;
}

export class ValidationError extends AppError {
  public readonly details: ValidationErrorDetail[];

  constructor(message: string, details: ValidationErrorDetail[]) {
    super(message, 400, 'VALIDATION_ERROR');
    this.details = details;
  }

  static fromZodError(error: ZodError): ValidationError {
    const details = error.errors.map((err) => ({
      path: err.path.join('.'),
      message: err.message,
    }));

    return new ValidationError('Validation failed', details);
  }
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/lib/asyncHandler.ts
// ═══════════════════════════════════════════════════════════════════════════
import { Request, Response, NextFunction, RequestHandler } from 'express';

export function asyncHandler(fn: RequestHandler): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/lib/env.ts
// ═══════════════════════════════════════════════════════════════════════════
import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(3000),

  // Database
  DB_HOST: z.string(),
  DB_PORT: z.coerce.number().default(5432),
  DB_NAME: z.string(),
  DB_USER: z.string(),
  DB_PASSWORD: z.string(),
  DB_POOL_MAX: z.coerce.number().default(20),
  DB_IDLE_TIMEOUT: z.coerce.number().default(30000),
  DB_CONNECTION_TIMEOUT: z.coerce.number().default(5000),

  // JWT
  JWT_SECRET: z.string().min(32),
  JWT_EXPIRES_IN: z.string().default('1h'),
});

export type Env = z.infer<typeof envSchema>;

export const env = envSchema.parse(process.env);


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/lib/envelope.ts
// ═══════════════════════════════════════════════════════════════════════════
export interface SuccessEnvelope<T = any> {
  success: true;
  data: T;
  requestId: string;
}

export interface ErrorEnvelope {
  success: false;
  error: {
    code: string;
    message: string;
    details?: any;
  };
  requestId: string;
}

export function success<T>(data: T): Omit<SuccessEnvelope<T>, 'requestId'> {
  return {
    success: true,
    data,
  };
}

export function created<T>(data: T): Omit<SuccessEnvelope<T>, 'requestId'> {
  return {
    success: true,
    data,
  };
}

export function error(
  code: string,
  message: string,
  details?: any,
): Omit<ErrorEnvelope, 'requestId'> {
  return {
    success: false,
    error: {
      code,
      message,
      details,
    },
  };
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/lib/jwt.ts
// ═══════════════════════════════════════════════════════════════════════════
import jwt from 'jsonwebtoken';
import { env } from './env';

export interface TokenPayload {
  userId: string;
  email: string;
  role: 'user' | 'admin';
}

export function signToken(payload: TokenPayload): string {
  return jwt.sign(payload, env.JWT_SECRET, {
    expiresIn: env.JWT_EXPIRES_IN,
  });
}

export function verifyToken(token: string): TokenPayload {
  return jwt.verify(token, env.JWT_SECRET) as TokenPayload;
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/lib/password.ts
// ═══════════════════════════════════════════════════════════════════════════
import bcrypt from 'bcrypt';

const SALT_ROUNDS = 10;

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

export async function verifyPassword(
  password: string,
  hashedPassword: string,
): Promise<boolean> {
  return bcrypt.compare(password, hashedPassword);
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/middleware/auth.ts
// ═══════════════════════════════════════════════════════════════════════════
import { RequestHandler } from 'express';
import { UnauthorizedError } from '../errors/httpErrors';
import { verifyToken, TokenPayload } from '../lib/jwt';

declare global {
  namespace Express {
    interface Request {
      user?: TokenPayload;
    }
  }
}

export const authenticate: RequestHandler = (req, _res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    return next(new UnauthorizedError('Missing or invalid Authorization header'));
  }

  const token = authHeader.slice(7);

  try {
    const payload = verifyToken(token);
    req.user = payload;
    next();
  } catch {
    next(new UnauthorizedError('Invalid or expired token'));
  }
};

export const requireAdmin: RequestHandler = (req, _res, next) => {
  if (!req.user) {
    return next(new UnauthorizedError('Authentication required'));
  }

  if (req.user.role !== 'admin') {
    return next(new UnauthorizedError('Admin access required'));
  }

  next();
};

export const requireSelfOrAdmin: RequestHandler = (req, _res, next) => {
  if (!req.user) {
    return next(new UnauthorizedError('Authentication required'));
  }

  const targetUserId = req.params.id;
  const isSelf = req.user.userId === targetUserId;
  const isAdmin = req.user.role === 'admin';

  if (!isSelf && !isAdmin) {
    return next(new UnauthorizedError('Access denied'));
  }

  next();
};


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/middleware/errorHandler.ts
// ═══════════════════════════════════════════════════════════════════════════
import { Request, Response, NextFunction } from 'express';
import { AppError } from '../errors/AppError';
import { ValidationError } from '../errors/zod';
import { error } from '../lib/envelope';
import { env } from '../lib/env';

export function errorHandler(
  err: Error,
  req: Request,
  res: Response,
  _next: NextFunction,
): void {
  const requestId = req.id || 'unknown';

  // Log error (in production, use proper logging)
  console.error(`[${requestId}] Error:`, err);

  // Handle known application errors
  if (err instanceof ValidationError) {
    res.status(err.statusCode).json({
      ...error(err.code, err.message, err.details),
      requestId,
    });
    return;
  }

  if (err instanceof AppError) {
    res.status(err.statusCode).json({
      ...error(err.code, err.message),
      requestId,
    });
    return;
  }

  // Handle unknown errors
  const statusCode = 500;
  const message =
    env.NODE_ENV === 'production' ? 'Internal Server Error' : err.message;

  res.status(statusCode).json({
    ...error('INTERNAL_ERROR', message),
    requestId,
  });
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/middleware/notFound.ts
// ═══════════════════════════════════════════════════════════════════════════
import { Request, Response, NextFunction } from 'express';
import { NotFoundError } from '../errors/httpErrors';

export function notFound(req: Request, _res: Response, next: NextFunction): void {
  next(new NotFoundError(`Route ${req.method} ${req.path} not found`));
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/middleware/requestId.ts
// ═══════════════════════════════════════════════════════════════════════════
import { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'crypto';

declare global {
  namespace Express {
    interface Request {
      id: string;
    }
  }
}

export function requestId(req: Request, res: Response, next: NextFunction): void {
  const id = (req.headers['x-request-id'] as string) || randomUUID();
  req.id = id;
  res.setHeader('X-Request-Id', id);
  next();
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/middleware/validate.ts
// ═══════════════════════════════════════════════════════════════════════════
import { Request, Response, NextFunction } from 'express';
import { AnyZodObject, ZodError } from 'zod';
import { ValidationError } from '../errors/zod';

export function validate(schema: AnyZodObject) {
  return async (req: Request, _res: Response, next: NextFunction) => {
    try {
      await schema.parseAsync({
        body: req.body,
        query: req.query,
        params: req.params,
      });
      next();
    } catch (err) {
      if (err instanceof ZodError) {
        next(ValidationError.fromZodError(err));
      } else {
        next(err);
      }
    }
  };
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/repositories/transferCredits.ts
// ═══════════════════════════════════════════════════════════════════════════
import { Pool } from 'pg';
import { withTransaction } from '../db/transaction';
import { query } from '../db/query';
import { BadRequestError, NotFoundError } from '../errors/httpErrors';

export interface TransferCreditsInput {
  fromUserId: string;
  toUserId: string;
  amount: number;
}

export async function transferCredits(
  pool: Pool,
  input: TransferCreditsInput,
): Promise<void> {
  const { fromUserId, toUserId, amount } = input;

  if (amount <= 0) {
    throw new BadRequestError('Transfer amount must be positive');
  }

  if (fromUserId === toUserId) {
    throw new BadRequestError('Cannot transfer credits to yourself');
  }

  await withTransaction(pool, async (tx) => {
    // Lock rows in deterministic order to prevent deadlocks
    const ids = [fromUserId, toUserId].sort();

    const locked = await query<{ id: string; credits: number }>(
      tx,
      `SELECT id, credits FROM users WHERE id = ANY($1::uuid[]) FOR UPDATE`,
      [ids],
    );

    if (locked.rows.length !== 2) {
      throw new NotFoundError('One or both users not found');
    }

    const fromUser = locked.rows.find((u) => u.id === fromUserId);
    const toUser = locked.rows.find((u) => u.id === toUserId);

    if (!fromUser || !toUser) {
      throw new NotFoundError('User not found');
    }

    if (fromUser.credits < amount) {
      throw new BadRequestError('Insufficient credits');
    }

    // Debit sender
    await query(tx, `UPDATE users SET credits = credits - $1 WHERE id = $2`, [
      amount,
      fromUserId,
    ]);

    // Credit receiver
    await query(tx, `UPDATE users SET credits = credits + $1 WHERE id = $2`, [
      amount,
      toUserId,
    ]);
  });
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/repositories/user.types.ts
// ═══════════════════════════════════════════════════════════════════════════
export interface User {
  id: string;
  email: string;
  passwordHash: string;
  name: string;
  dateOfBirth: string | null;
  credits: number;
  role: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateUserInput {
  email: string;
  passwordHash: string;
  name: string;
  dateOfBirth?: string;
  credits?: number;
  role?: string;
}

export interface UpdateUserInput {
  email?: string;
  name?: string;
  dateOfBirth?: string;
  credits?: number;
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/repositories/UserRepository.ts
// ═══════════════════════════════════════════════════════════════════════════
import { Pool } from 'pg';
import { query, Queryable } from '../db/query';
import { User, CreateUserInput, UpdateUserInput } from './user.types';

interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  name: string;
  date_of_birth: string | null;
  credits: number;
  role: string;
  created_at: Date;
  updated_at: Date;
}

function rowToUser(row: UserRow): User {
  return {
    id: row.id,
    email: row.email,
    passwordHash: row.password_hash,
    name: row.name,
    dateOfBirth: row.date_of_birth,
    credits: row.credits,
    role: row.role,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export class UserRepository {
  constructor(private readonly db: Queryable) {}

  async create(input: CreateUserInput): Promise<User> {
    const result = await query<UserRow>(
      this.db,
      `INSERT INTO users (email, password_hash, name, date_of_birth, credits, role)
       VALUES (LOWER($1), $2, $3, $4, $5, $6)
       RETURNING *`,
      [
        input.email,
        input.passwordHash,
        input.name,
        input.dateOfBirth || null,
        input.credits || 0,
        input.role || 'user',
      ],
    );

    return rowToUser(result.rows[0]);
  }

  async findById(id: string): Promise<User | null> {
    const result = await query<UserRow>(
      this.db,
      `SELECT * FROM users WHERE id = $1`,
      [id],
    );

    return result.rows[0] ? rowToUser(result.rows[0]) : null;
  }

  async findByEmail(email: string): Promise<User | null> {
    const result = await query<UserRow>(
      this.db,
      `SELECT * FROM users WHERE LOWER(email) = LOWER($1)`,
      [email],
    );

    return result.rows[0] ? rowToUser(result.rows[0]) : null;
  }

  async update(id: string, input: UpdateUserInput): Promise<User | null> {
    const fields: string[] = [];
    const values: any[] = [];
    let paramIndex = 1;

    if (input.email !== undefined) {
      fields.push(`email = LOWER($${paramIndex++})`);
      values.push(input.email);
    }

    if (input.name !== undefined) {
      fields.push(`name = $${paramIndex++}`);
      values.push(input.name);
    }

    if (input.dateOfBirth !== undefined) {
      fields.push(`date_of_birth = $${paramIndex++}`);
      values.push(input.dateOfBirth);
    }

    if (input.credits !== undefined) {
      fields.push(`credits = $${paramIndex++}`);
      values.push(input.credits);
    }

    if (fields.length === 0) {
      return this.findById(id);
    }

    fields.push(`updated_at = NOW()`);
    values.push(id);

    const result = await query<UserRow>(
      this.db,
      `UPDATE users SET ${fields.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
      values,
    );

    return result.rows[0] ? rowToUser(result.rows[0]) : null;
  }

  async delete(id: string): Promise<boolean> {
    const result = await query(this.db, `DELETE FROM users WHERE id = $1`, [id]);
    return result.rowCount !== null && result.rowCount > 0;
  }

  async list(opts: { limit?: number; offset?: number } = {}): Promise<User[]> {
    const limit = opts.limit ?? 20;
    const offset = opts.offset ?? 0;

    const result = await query<UserRow>(
      this.db,
      `SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
      [limit, offset],
    );

    return result.rows.map(rowToUser);
  }
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/routes/demo.ts
// ═══════════════════════════════════════════════════════════════════════════
import { Router } from 'express';
import { asyncHandler } from '../lib/asyncHandler';
import { success } from '../lib/envelope';

const router = Router();

router.get(
  '/',
  asyncHandler(async (_req, res) => {
    res.json(success({ message: 'Demo route works!' }));
  }),
);

export default router;


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/routes/users.ts
// ═══════════════════════════════════════════════════════════════════════════
import { Router } from 'express';
import { asyncHandler } from '../lib/asyncHandler';
import { validate } from '../middleware/validate';
import {
  createUserSchema,
  updateUserSchema,
  userIdSchema,
  loginSchema,
} from '../validation/user.schema';
import { UserRepository } from '../repositories/UserRepository';
import { pool } from '../db/pool';
import { hashPassword, verifyPassword } from '../lib/password';
import { success, created } from '../lib/envelope';
import { BadRequestError, NotFoundError } from '../errors/httpErrors';
import { authenticate, requireSelfOrAdmin, requireAdmin } from '../middleware/auth';
import { signToken } from '../lib/jwt';

const router = Router();
const userRepo = new UserRepository(pool);

// POST /api/users - Register (public)
router.post(
  '/',
  validate(createUserSchema),
  asyncHandler(async (req, res) => {
    const { password, ...userData } = req.body;
    const passwordHash = await hashPassword(password);

    const user = await userRepo.create({ ...userData, passwordHash });

    const { passwordHash: _, ...safeUser } = user as any;
    res.status(201).json(created(safeUser));
  }),
);

// POST /api/users/login - Login (public)
router.post(
  '/login',
  validate(loginSchema),
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    const user = await userRepo.findByEmail(email);
    if (!user) {
      throw new BadRequestError('Invalid email or password');
    }

    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) {
      throw new BadRequestError('Invalid email or password');
    }

    const token = signToken({
      userId: user.id,
      email: user.email,
      role: user.role as 'user' | 'admin',
    });

    res.json(
      success({
        token,
        user: { id: user.id, email: user.email, name: user.name },
      }),
    );
  }),
);

// GET /api/users - List users (admin only)
router.get(
  '/',
  authenticate,
  requireAdmin,
  asyncHandler(async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit as string) || 20, 100);
    const offset = parseInt(req.query.offset as string) || 0;

    const users = await userRepo.list({ limit, offset });

    // Remove password hashes
    const safeUsers = users.map(({ passwordHash, ...user }) => user);

    res.json(success(safeUsers));
  }),
);

// GET /api/users/:id - Get user (self or admin)
router.get(
  '/:id',
  validate(userIdSchema),
  authenticate,
  requireSelfOrAdmin,
  asyncHandler(async (req, res) => {
    const user = await userRepo.findById(req.params.id);
    if (!user) {
      throw new NotFoundError('User not found');
    }

    const { passwordHash: _, ...safeUser } = user as any;
    res.json(success(safeUser));
  }),
);

// PATCH /api/users/:id - Update user (self or admin)
router.patch(
  '/:id',
  validate(updateUserSchema),
  authenticate,
  requireSelfOrAdmin,
  asyncHandler(async (req, res) => {
    const user = await userRepo.update(req.params.id, req.body);
    if (!user) {
      throw new NotFoundError('User not found');
    }

    const { passwordHash: _, ...safeUser } = user as any;
    res.json(success(safeUser));
  }),
);

// DELETE /api/users/:id - Delete user (admin only)
router.delete(
  '/:id',
  validate(userIdSchema),
  authenticate,
  requireAdmin,
  asyncHandler(async (req, res) => {
    const deleted = await userRepo.delete(req.params.id);
    if (!deleted) {
      throw new NotFoundError('User not found');
    }

    res.status(204).send();
  }),
);

export default router;


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/types/express.d.ts
// ═══════════════════════════════════════════════════════════════════════════
import { TokenPayload } from '../lib/jwt';

declare global {
  namespace Express {
    interface Request {
      id: string;
      user?: TokenPayload;
    }
  }
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE: src/validation/user.schema.ts
// ═══════════════════════════════════════════════════════════════════════════
import { z } from 'zod';

export const createUserSchema = z.object({
  body: z.object({
    email: z.string().email('Invalid email format'),
    password: z
      .string()
      .min(8, 'Password must be at least 8 characters')
      .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
      .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
      .regex(/[0-9]/, 'Password must contain at least one number')
      .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
    name: z.string().min(1, 'Name is required').max(255),
    dateOfBirth: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Date must be in YYYY-MM-DD format').optional(),
    credits: z.number().int().min(0).optional(),
  }),
});

export const updateUserSchema = z.object({
  params: z.object({
    id: z.string().uuid('Invalid user ID format'),
  }),
  body: z.object({
    email: z.string().email('Invalid email format').optional(),
    name: z.string().min(1).max(255).optional(),
    dateOfBirth: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Date must be in YYYY-MM-DD format').optional(),
    credits: z.number().int().min(0).optional(),
  }),
});

export const userIdSchema = z.object({
  params: z.object({
    id: z.string().uuid('Invalid user ID format'),
  }),
});

export const loginSchema = z.object({
  body: z.object({
    email: z.string().email('Invalid email format'),
    password: z.string().min(1, 'Password is required'),
  }),
});
