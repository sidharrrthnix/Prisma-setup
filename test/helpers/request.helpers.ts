import request, { Response } from 'supertest';
import { pool } from '../../src/db/pool';
import { createApp } from '../../src/server';

export const api = request(createApp({ pool }));
export function expectSuccess(res: Response, statusCode = 200): void {
  expect(res.status).toBe(statusCode);
  expect(res.body).toHaveProperty('success', true);
  expect(res.body).toHaveProperty('data');
}
export function expectError(res: Response, statusCode: number, messageContains?: string): void {
  expect(res.status).toBe(statusCode);
  expect(res.body).toHaveProperty('success', false);
  expect(res.body).toHaveProperty('error');
  if (messageContains) {
    expect(res.body.error.message.toLowerCase()).toContain(messageContains.toLowerCase());
  }
}
export function expectValidationerror(res: Response): void {
  expect(res.status).toBe(400);
  expect(res.body).toHaveProperty('success', false);
  expect(res.body.error).toHaveProperty('code', 'VALIDATION_ERROR');
}
