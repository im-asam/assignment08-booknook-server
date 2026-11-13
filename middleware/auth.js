const jwt = require("jsonwebtoken");
const { ObjectId } = require("mongodb");
const { getDb } = require("../db");

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
    decoded = jwt.verify(token, process.env.BETTER_AUTH_SECRET);
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

module.exports = { verifyToken };
