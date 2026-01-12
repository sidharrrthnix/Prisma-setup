import { connectWithRetry } from './db/prisma';
import { env } from './lib/env';
import { createApp } from './server';

async function main() {
  await connectWithRetry();
  const app = createApp();
  app.listen(env.PORT, () => {
    console.log(`${env.APP_NAME} listening on port ${env.PORT}`);
  });
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
