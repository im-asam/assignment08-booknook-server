require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { ObjectId } = require("mongodb");
const { getDb } = require("./db");
const { verifyToken } = require("./middleware/auth");

const app = express();

// CORS: allow the client origin if configured, otherwise allow all (dev).
app.use(
  cors({
    origin: process.env.CLIENT_URL || true,
    credentials: true,
  })
);
app.use(express.json());

// Health check — must NOT touch the DB, so it works even without a valid MONGODB_URI.
app.get("/", (req, res) => {
  res.json({ status: "ok", message: "BookNook server is running" });
});

// ---------- Books ----------

// GET /books — public. ?limit=n, ?sort=newest, ?email=xxx (My Books).
app.get("/books", async (req, res, next) => {
  try {
    const db = await getDb();
    const query = {};
    if (req.query.email) {
      query.addedByEmail = req.query.email;
    }
    let cursor = db.collection("books").find(query).sort({ addedAt: -1 });
    const limit = parseInt(req.query.limit, 10);
    if (!Number.isNaN(limit) && limit > 0) {
      cursor = cursor.limit(limit);
    }
    const books = await cursor.toArray();
    res.json(books);
  } catch (err) {
    next(err);
  }
});

// GET /books/:id — public.
app.get("/books/:id", async (req, res, next) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ error: "Invalid book id" });
    }
    const db = await getDb();
    const book = await db
      .collection("books")
      .findOne({ _id: new ObjectId(req.params.id) });
    if (!book) {
      return res.status(404).json({ error: "Book not found" });
    }
    res.json(book);
  } catch (err) {
    next(err);
  }
});

// POST /books — protected. Adds a book; server sets addedAt and availableCopies.
app.post("/books", verifyToken, async (req, res, next) => {
  try {
    const { title, author, category, image, description, totalCopies, addedBy, addedByEmail } =
      req.body || {};
    if (
      !title ||
      !author ||
      !category ||
      !image ||
      !description ||
      totalCopies === undefined ||
      totalCopies === null ||
      !addedBy ||
      !addedByEmail
    ) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    const total = Number(totalCopies);
    if (!Number.isFinite(total) || total < 1) {
      return res.status(400).json({ error: "totalCopies must be a number >= 1" });
    }
    const book = {
      title,
      author,
      category,
      image,
      description,
      totalCopies: total,
      availableCopies: total,
      addedBy,
      addedByEmail,
      addedAt: new Date(),
    };
    const db = await getDb();
    const result = await db.collection("books").insertOne(book);
    res.status(201).json({ _id: result.insertedId, ...book });
  } catch (err) {
    next(err);
  }
});

// PATCH /books/:id — protected, owner only.
app.patch("/books/:id", verifyToken, async (req, res, next) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ error: "Invalid book id" });
    }
    const db = await getDb();
    const books = db.collection("books");
    const book = await books.findOne({ _id: new ObjectId(req.params.id) });
    if (!book) {
      return res.status(404).json({ error: "Book not found" });
    }
    if (book.addedByEmail !== req.userEmail) {
      return res.status(403).json({ error: "Forbidden: only the owner can edit this book" });
    }

    const allowed = ["title", "author", "category", "image", "description", "totalCopies"];
    const updates = {};
    for (const key of allowed) {
      if (req.body && req.body[key] !== undefined) {
        updates[key] = key === "totalCopies" ? Number(req.body[key]) : req.body[key];
      }
    }
    if (
      updates.totalCopies !== undefined &&
      (!Number.isFinite(updates.totalCopies) || updates.totalCopies < 1)
    ) {
      return res.status(400).json({ error: "totalCopies must be a number >= 1" });
    }
    // If totalCopies changes, shift availableCopies by the same delta (clamp >= 0).
    if (updates.totalCopies !== undefined && updates.totalCopies !== book.totalCopies) {
      const delta = updates.totalCopies - book.totalCopies;
      updates.availableCopies = Math.max(0, book.availableCopies + delta);
    }

    await books.updateOne({ _id: book._id }, { $set: updates });
    const updated = await books.findOne({ _id: book._id });
    res.json(updated);
  } catch (err) {
    next(err);
  }
});

// DELETE /books/:id — protected, owner only. Also deletes its borrows.
app.delete("/books/:id", verifyToken, async (req, res, next) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ error: "Invalid book id" });
    }
    const db = await getDb();
    const books = db.collection("books");
    const book = await books.findOne({ _id: new ObjectId(req.params.id) });
    if (!book) {
      return res.status(404).json({ error: "Book not found" });
    }
    if (book.addedByEmail !== req.userEmail) {
      return res.status(403).json({ error: "Forbidden: only the owner can delete this book" });
    }
    await books.deleteOne({ _id: book._id });
    await db.collection("borrows").deleteMany({ bookId: req.params.id });
    res.json({ deleted: true });
  } catch (err) {
    next(err);
  }
});

// 404 for unknown routes.
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// Central error handler — always return JSON, never crash the process.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: err.message || "Internal server error" });
});

// Only listen when run directly; Vercel serverless imports the app without listening.
if (require.main === module) {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => {
    console.log(`BookNook server is running on port ${PORT}`);
  });
}

module.exports = app;
