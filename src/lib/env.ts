import * as dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config();

const envSchema = z.object({
  APP_NAME: z.string().min(1, 'APP_NAME is required'),
  PORT: z.coerce.number().min(0).max(65535).default(3000),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters long'),

  DATABASE_URL: z.string().url('DATABASE_URL must be a valid URL'),
  DB_POOL_MAX: z.coerce.number().min(1).max(100).default(10),
  DB_CONNECTION_TIMEOUT: z.coerce.number().min(0).max(30000).default(10000),
  DB_POOL_TIMEOUT: z.coerce.number().min(0).max(30000).default(10000),
  DB_CONNECT_RETRIES: z.coerce.number().min(0).max(10).default(3),
  DB_CONNECT_RETRY_DELAY: z.coerce.number().min(0).max(5000).default(1000),
});

export type Env = z.infer<typeof envSchema>;

export function parseEnv(input: NodeJS.ProcessEnv = process.env): Env {
  return envSchema.parse(input);
}

export const env: Env = parseEnv();

export function getDatabaseUrl(): string {
  const url = new URL(env.DATABASE_URL);
  url.searchParams.set('connection_limit', String(env.DB_POOL_MAX));
  url.searchParams.set('pool_timeout', String(Math.floor(env.DB_POOL_TIMEOUT / 1000)));
  url.searchParams.set('connect_timeout', String(Math.floor(env.DB_CONNECTION_TIMEOUT / 1000)));
  return url.toString();
}
