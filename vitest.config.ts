import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['test/**/*.test.ts'],
    testTimeout: 60_000,
    hookTimeout: 60_000,
    fileParallelism: false,
    env: {
      DATABASE_URL: 'postgresql://testuser:testpass@localhost:5433/testdb', // Changed to 5433
      APP_NAME: 'test-app',
      PORT: '3000',
      NODE_ENV: 'test',
      DB_SSL: 'false',
    },
  },
});
