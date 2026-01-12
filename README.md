# Node.js TypeScript Scaffold with Prisma

A production-ready Node.js/Express API boilerplate with TypeScript, Prisma ORM, JWT authentication, and comprehensive testing.

## Stack

- **Runtime**: Node.js 20+
- **Framework**: Express 5
- **Database**: PostgreSQL + Prisma ORM 6
- **Language**: TypeScript 5
- **Auth**: JWT (jsonwebtoken)
- **Testing**: Vitest + Supertest
- **Validation**: Zod
- **Tools**: ESLint, Prettier, Docker Compose

## Quick Start

### Prerequisites
- Node.js ≥ 20
- Docker & Docker Compose
- Git

### Setup

```bash
# 1. Clone and install
git clone <repo>
cd prisma-setup
npm install

# 2. Environment variables
cp env-sample .env
# Edit .env if needed (default values work with docker-compose)

# 3. Start database
docker-compose up -d

# 4. Setup database
npx prisma db push

# 5. Start development server
npm run dev
```

Server runs on `http://localhost:3000`

## Available Scripts

| Script | Purpose |
|--------|---------|
| `npm run dev` | Start development server (hot reload) |
| `npm run build` | Compile TypeScript to JavaScript |
| `npm start` | Run compiled app |
| `npm test` | Run tests |
| `npm run test:watch` | Watch mode for tests |
| `npm run lint` | Check code with ESLint |
| `npm run format:write` | Format code with Prettier |
| `npx prisma studio` | Open Prisma GUI for database |
| `npm run docker:up` | Start PostgreSQL |
| `npm run docker:down` | Stop PostgreSQL |

## Project Structure

```
src/
├── db/               # Database & Prisma setup
├── errors/           # Custom error classes
├── lib/              # Utilities (env, jwt, password, etc)
├── middleware/       # Express middleware
├── repositories/     # Data access layer
├── routes/           # API endpoints
├── validation/       # Zod schemas
├── server.ts         # Express app setup
└── index.ts          # Entry point

prisma/
└── schema.prisma     # Database schema

test/
├── integration/      # Integration tests
├── helpers/          # Test utilities
└── factories/        # Test data factories
```

## API Endpoints

### Users
- `POST /api/users` - Create user
- `POST /api/users/login` - Login
- `GET /api/users` - List users (admin only)
- `GET /api/users/:id` - Get user
- `PATCH /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user
- `POST /api/users/transfer-credits` - Transfer credits between users

## Database

Uses PostgreSQL with Prisma ORM. Schema includes:
- Users (with role-based access control)
- Automatic timestamps (createdAt, updatedAt)
- Email uniqueness constraint
- Credits system for transfers

### Migrations

```bash
# Create new migration
npx prisma migrate dev --name <migration_name>

# Deploy migrations (production)
npx prisma migrate deploy
```

## Authentication

JWT-based authentication:
- `POST /api/users/login` returns JWT token
- Include token in `Authorization: Bearer <token>` header
- Decode in middleware to protect routes

## Environment Variables

Create `.env` from `env-sample`:

```env
APP_NAME=my-app
NODE_ENV=development
PORT=3000
DATABASE_URL=postgresql://devuser:devpass@localhost:5434/devdb
JWT_SECRET=your-secret-key-min-32-chars
DB_CONNECT_RETRIES=3
DB_CONNECT_RETRY_DELAY=1000
```

## Testing

```bash
# Run all tests
npm test

# Watch mode
npm run test:watch

# With coverage
npm run test:cov

# Docker + tests
npm run test:docker
```

## License

MIT

