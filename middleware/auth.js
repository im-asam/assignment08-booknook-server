const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { ObjectId } = require("mongodb");
const { getDb } = require("../db");

// The client app's BetterAuth JWT plugin signs tokens with EdDSA (Ed25519)
// using a key pair it manages itself — NOT with BETTER_AUTH_SECRET. The
// public key is published at the client's /api/auth/jwks endpoint, so this
// server verifies tokens against that JWKS (cached in memory, refreshed
// when a token's `kid` is unknown, e.g. after key rotation).
// As a fallback, HS256 tokens signed with the shared BETTER_AUTH_SECRET
// are also accepted, so either client configuration keeps working.

const CLIENT_BASE = (
  process.env.CLIENT_URL || "https://assignment08-booknook-client.vercel.app"
).replace(/\/$/, "");

const JWKS_URL = `${CLIENT_BASE}/api/auth/jwks`;
const JWKS_TTL_MS = 10 * 60 * 1000;

let jwksCache = null; // { keys: [...], fetchedAt: number }

async function fetchJwks() {
  const res = await fetch(JWKS_URL, { signal: AbortSignal.timeout(8000) });
  if (!res.ok) {
    throw new Error(`JWKS fetch failed (${res.status})`);
  }
  const data = await res.json();
  jwksCache = { keys: data.keys || [], fetchedAt: Date.now() };
  return jwksCache.keys;
}

async function getJwksKeys(forceRefresh = false) {
  const stale =
    !jwksCache || Date.now() - jwksCache.fetchedAt > JWKS_TTL_MS;
  if (forceRefresh || stale) {
    return fetchJwks();
  }
  return jwksCache.keys;
}

function verifyWithJwks(token, kid) {
  return getJwksKeys()
    .then(async (keys) => {
      let jwk = keys.find((k) => k.kid === kid);
      if (!jwk) {
        // Unknown kid — the client may have rotated keys; refresh once.
        jwk = (await getJwksKeys(true)).find((k) => k.kid === kid);
      }
      if (!jwk) {
        throw new Error("No matching key in JWKS");
      }
      const publicKey = crypto.createPublicKey({ key: jwk, format: "jwk" });
      return jwt.verify(token, publicKey, { algorithms: ["EdDSA"] });
    });
}

// Verifies a BetterAuth JWT and returns its decoded claims.
// Throws on any verification failure.
async function verifyJwt(token) {
  const header = jwt.decode(token, { complete: true })?.header;

  // Asymmetric token (what the JWT plugin issues): verify via JWKS.
  if (header && header.alg && header.alg !== "HS256") {
    return verifyWithJwks(token, header.kid);
  }

  // Symmetric token: verify with the shared secret.
  const secret = process.env.BETTER_AUTH_SECRET;
  if (secret) {
    try {
      return jwt.verify(token, secret, { algorithms: ["HS256"] });
    } catch (err) {
      // Fall through to the JWKS attempt (e.g. HS256 header on a
      // misconfigured client); if that fails too, the token is rejected.
    }
  }
  if (header && header.kid) {
    return verifyWithJwks(token, header.kid);
  }
  throw new Error("JWT verification failed");
}

// Verifies the BetterAuth JWT (issued by the client app's JWT plugin).
// Token's `sub` claim is the user's id. Looks up the user in the `user`
// collection to resolve their email; falls back to decoded claims and
// never hard-fails on a missing user doc once the token itself verified.
async function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  let decoded;
  try {
    decoded = await verifyJwt(token);
  } catch (err) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  req.userId = decoded.sub || null;
  req.userEmail = decoded.email || null;

  // Resolve email from the user collection (created by the client app).
  if (decoded.sub && ObjectId.isValid(decoded.sub)) {
    try {
      const db = await getDb();
      const user = await db.collection("user").findOne({ _id: new ObjectId(decoded.sub) });
      if (user && user.email) {
        req.userEmail = user.email;
      }
    } catch (err) {
      // DB lookup failure must not reject an otherwise valid token.
      console.error("User lookup failed:", err.message);
    }
  }

  // Last resort identity: email claim, else the sub itself.
  if (!req.userEmail) {
    req.userEmail = decoded.sub || null;
  }

  next();
}

module.exports = { verifyToken, verifyJwt };
