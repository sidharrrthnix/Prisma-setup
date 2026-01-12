import { parseEnv } from '../src/lib/env';

describe('parseEnv', () => {
  it('should parse the environment variables', () => {
    const env = parseEnv({
      APP_NAME: 'test',
      PORT: '3000',
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://user:pass@localhost:5432/testdb',
      JWT_SECRET: 'abcdefghijklmnopqrstuvwxyz123456',
    });
    expect(env.APP_NAME).toBe('test');
    expect(env.PORT).toBe(3000);
    expect(env.NODE_ENV).toBe('test');
    expect(env.DATABASE_URL).toBe('postgresql://user:pass@localhost:5432/testdb');
  });

  it('should throw when APP_NAME is not provided', () => {
    expect(() =>
      parseEnv({
        PORT: '3000',
        NODE_ENV: 'test',
        DATABASE_URL: 'postgresql://user:pass@localhost:5432/testdb',
      }),
    ).toThrow(/APP_NAME/i);
  });

  it('should throw when PORT is out of range', () => {
    expect(() =>
      parseEnv({
        APP_NAME: 'test',
        PORT: '65536',
        NODE_ENV: 'test',
        DATABASE_URL: 'postgresql://user:pass@localhost:5432/testdb',
      }),
    ).toThrow(/PORT/i);
  });
});
