# BookNook Server

Express API server for **BookNook**, a small online library (Programming Hero Assignment 8, B14-A8). Built with Node.js + Express + MongoDB (native driver) + jsonwebtoken. CommonJS, no TypeScript.

## Routes

All routes are under the root (no `/api` prefix). Protected routes require `Authorization: Bearer <token>` (a BetterAuth JWT, verified with `BETTER_AUTH_SECRET`).

| Method | Route           | Auth      | Description |
| ------ | --------------- | --------- | ----------- |
| GET    | `/`             | Public    | Health check — `{ status: "ok", message: "BookNook server is running" }` |
| GET    | `/books`        | Public    | All books, newest first. `?limit=n`, `?sort=newest`, `?email=xxx` (filter by `addedByEmail`) |
| GET    | `/books/:id`    | Public    | One book by id |
| POST   | `/books`        | Protected | Add a book. Server sets `addedAt` and `availableCopies = totalCopies` |
| PATCH  | `/books/:id`    | Protected, owner only | Edit a book; `totalCopies` changes shift `availableCopies` by the same delta (clamped >= 0) |
| DELETE | `/books/:id`    | Protected, owner only | Delete a book and all its borrows |
| POST   | `/borrows`      | Protected | Borrow a book. Rejects double borrows (409) and out-of-stock books (400); decrements `availableCopies` |
| GET    | `/borrows`      | Protected | The caller's borrows (`?email=` must match the token user), newest first |
| DELETE | `/borrows/:id`  | Protected | Return a book; restores one copy (only if below `totalCopies`) |

## Database

MongoDB database `booknook`, collections `books` and `borrows`. The same database also holds BetterAuth's `user` collection (created by the client app) — the JWT middleware reads it to resolve the caller's email. The MongoDB client is lazy and cached (connects on first use, reused across calls — serverless-safe).

## Env vars

Copy `.env.example` to `.env` and fill in the real values:

- `MONGODB_URI` — MongoDB Atlas connection string (database `booknook`)
- `BETTER_AUTH_SECRET` — shared secret for JWT verification; must match the client's value exactly
- `PORT` — local port (default `5000`)
- `CLIENT_URL` — client origin for CORS; if unset, all origins are allowed

## Run locally

```bash
npm install
npm run dev    # or: npm start
```

## Deploy

Vercel: `api/index.js` exports the Express app (no `listen()` there) and `vercel.json` rewrites all routes to it. Set `MONGODB_URI`, `BETTER_AUTH_SECRET`, and `CLIENT_URL` in the Vercel project env vars.
