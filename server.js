const path = require("path");
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const PORT = process.env.PORT || 3000;

// Remove accidental spaces or quotes that can get pasted into hosting env variables
const clean = (v) => String(v || "").trim().replace(/^["']+|["']+$/g, "");
const MONGODB_URI = clean(process.env.MONGODB_URI);
const JWT_SECRET = clean(process.env.JWT_SECRET) || "change-me-in-production";

if (!/^mongodb(\+srv)?:\/\//.test(MONGODB_URI)) {
  console.error("MONGODB_URI is missing or wrong. It must start with mongodb+srv://");
  console.error("It currently starts with:", JSON.stringify(MONGODB_URI.slice(0, 12)), "length:", MONGODB_URI.length);
  console.error("Env variable names found:", Object.keys(process.env).filter((k) => /MONGO|JWT|URI|SECRET/i.test(k)).join(", ") || "none");
  process.exit(1);
}
if (!clean(process.env.JWT_SECRET)) {
  console.warn("Warning: JWT_SECRET is not set. Set it in your hosting environment variables.");
}

/* ---------- Database models ---------- */

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ["customer", "admin"], default: "customer" }
  },
  { timestamps: true }
);

const productSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    category: { type: String, default: "General" },
    price: { type: Number, required: true, min: 0 },
    stock: { type: Number, required: true, min: 0 },
    imageUrl: { type: String, default: "" }
  },
  { timestamps: true }
);

const orderSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    items: [
      {
        product: { type: mongoose.Schema.Types.ObjectId, ref: "Product" },
        name: String,
        price: Number,
        quantity: Number
      }
    ],
    total: { type: Number, required: true },
    status: { type: String, enum: ["PENDING", "APPROVED", "REJECTED"], default: "PENDING" },
    adminNote: { type: String, default: "" },
    reviewedAt: Date
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Product = mongoose.model("Product", productSchema);
const Order = mongoose.model("Order", orderSchema);

/* ---------- Helpers ---------- */

const app = express();
app.use(express.json({ limit: "100kb" }));

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });

function signToken(user) {
  return jwt.sign({ id: String(user._id), role: user.role, name: user.name }, JWT_SECRET, { expiresIn: "8h" });
}

function publicUser(user) {
  return { id: String(user._id), name: user.name, email: user.email, role: user.role };
}

/* Authentication: verifies the JWT on every protected request */
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Please log in first." });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { id: payload.id, role: payload.role, name: payload.name };
    next();
  } catch (e) {
    res.status(401).json({ error: "Invalid or expired session. Please log in again." });
  }
}

/* Authorization: only the listed roles may continue */
const requireRole = (...roles) => (req, res, next) =>
  roles.includes(req.user.role)
    ? next()
    : res.status(403).json({ error: "Access denied: this action is not allowed for your role." });

function cleanProduct(body) {
  const name = String(body.name || "").trim();
  const price = Number(body.price);
  const stock = Number(body.stock);
  const imageUrl = String(body.imageUrl || "").trim();
  if (!name) throw bad("Product name is required.");
  if (!Number.isFinite(price) || price < 0) throw bad("Price must be a number, 0 or more.");
  if (!Number.isInteger(stock) || stock < 0) throw bad("Stock must be a whole number, 0 or more.");
  if (imageUrl && !/^https?:\/\//i.test(imageUrl)) throw bad("Image URL must start with http:// or https://");
  return {
    name,
    description: String(body.description || "").trim(),
    category: String(body.category || "General").trim() || "General",
    price,
    stock,
    imageUrl
  };
}

const idOr400 = (id) => {
  if (!mongoose.isValidObjectId(id)) throw bad("Invalid id.");
  return id;
};

/* ---------- Auth routes ---------- */

app.post("/api/auth/register", wrap(async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!name) throw bad("Name is required.");
  if (!/^\S+@\S+\.\S+$/.test(email)) throw bad("Enter a valid email address.");
  if (password.length < 6) throw bad("Password must be at least 6 characters.");
  try {
    // Public sign-up always creates a customer. Admins cannot be created from the API.
    const user = await User.create({ name, email, passwordHash: await bcrypt.hash(password, 10), role: "customer" });
    res.status(201).json({ token: signToken(user), user: publicUser(user) });
  } catch (e) {
    if (e.code === 11000) throw bad("An account with this email already exists.", 409);
    throw e;
  }
}));

app.post("/api/auth/login", wrap(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    throw bad("Incorrect email or password.", 401);
  }
  res.json({ token: signToken(user), user: publicUser(user) });
}));

app.get("/api/auth/me", auth, wrap(async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) throw bad("Account not found.", 401);
  res.json({ user: publicUser(user) });
}));

/* ---------- Product routes ---------- */

// Anyone can browse products
app.get("/api/products", wrap(async (req, res) => {
  res.json(await Product.find().sort({ createdAt: -1 }));
}));

// Only admins can manage products
app.post("/api/products", auth, requireRole("admin"), wrap(async (req, res) => {
  res.status(201).json(await Product.create(cleanProduct(req.body)));
}));

app.put("/api/products/:id", auth, requireRole("admin"), wrap(async (req, res) => {
  const product = await Product.findByIdAndUpdate(idOr400(req.params.id), cleanProduct(req.body), {
    new: true,
    runValidators: true
  });
  if (!product) throw bad("Product not found.", 404);
  res.json(product);
}));

app.delete("/api/products/:id", auth, requireRole("admin"), wrap(async (req, res) => {
  const product = await Product.findByIdAndDelete(idOr400(req.params.id));
  if (!product) throw bad("Product not found.", 404);
  res.json({ deleted: true });
}));

/* ---------- Order routes ---------- */

// Customers place orders. Prices come from the database, never from the browser.
app.post("/api/orders", auth, requireRole("customer"), wrap(async (req, res) => {
  const items = Array.isArray(req.body.items) ? req.body.items : [];
  if (items.length === 0 || items.length > 50) throw bad("Your cart is empty.");

  const wanted = new Map();
  for (const it of items) {
    const id = String(it.productId);
    const qty = Number(it.quantity);
    if (!mongoose.isValidObjectId(id)) throw bad("Invalid product in cart.");
    if (!Number.isInteger(qty) || qty < 1 || qty > 99) throw bad("Quantity must be between 1 and 99.");
    wanted.set(id, (wanted.get(id) || 0) + qty);
  }

  const products = await Product.find({ _id: { $in: [...wanted.keys()] } });
  if (products.length !== wanted.size) throw bad("A product in your cart no longer exists.");

  const lines = [];
  let total = 0;
  for (const p of products) {
    const qty = wanted.get(String(p._id));
    if (p.stock < qty) throw bad(`Only ${p.stock} of "${p.name}" left in stock.`, 409);
    lines.push({ product: p._id, name: p.name, price: p.price, quantity: qty });
    total += p.price * qty;
  }

  // New orders always start as PENDING and wait for admin validation.
  const order = await Order.create({ user: req.user.id, items: lines, total, status: "PENDING" });
  res.status(201).json(order);
}));

// Customers see only their own orders
app.get("/api/orders/mine", auth, requireRole("customer"), wrap(async (req, res) => {
  res.json(await Order.find({ user: req.user.id }).sort({ createdAt: -1 }));
}));

// Admins see all orders (optionally filtered by status)
app.get("/api/orders", auth, requireRole("admin"), wrap(async (req, res) => {
  const filter = {};
  if (["PENDING", "APPROVED", "REJECTED"].includes(req.query.status)) filter.status = req.query.status;
  res.json(await Order.find(filter).sort({ createdAt: -1 }).populate("user", "name email"));
}));

// Admin validation: approve (reduces stock) or reject
app.patch("/api/orders/:id/approve", auth, requireRole("admin"), wrap(async (req, res) => {
  const id = idOr400(req.params.id);
  const note = String(req.body.note || "").slice(0, 200);

  // Claim the order atomically so it can only be processed once
  const order = await Order.findOneAndUpdate(
    { _id: id, status: "PENDING" },
    { $set: { status: "APPROVED", adminNote: note, reviewedAt: new Date() } },
    { new: true }
  );
  if (!order) throw bad("Order not found or already reviewed.", 409);

  const reduced = [];
  for (const line of order.items) {
    const result = await Product.updateOne(
      { _id: line.product, stock: { $gte: line.quantity } },
      { $inc: { stock: -line.quantity } }
    );
    if (result.modifiedCount !== 1) {
      // Not enough stock: undo the stock changes and put the order back to PENDING
      for (const r of reduced) await Product.updateOne({ _id: r.product }, { $inc: { stock: r.quantity } });
      await Order.updateOne({ _id: order._id }, { $set: { status: "PENDING", adminNote: "" }, $unset: { reviewedAt: "" } });
      throw bad(`Not enough stock for "${line.name}". Update stock or reject this order.`, 409);
    }
    reduced.push(line);
  }
  res.json(order);
}));

app.patch("/api/orders/:id/reject", auth, requireRole("admin"), wrap(async (req, res) => {
  const id = idOr400(req.params.id);
  const note = String(req.body.note || "").slice(0, 200);
  const order = await Order.findOneAndUpdate(
    { _id: id, status: "PENDING" },
    { $set: { status: "REJECTED", adminNote: note, reviewedAt: new Date() } },
    { new: true }
  );
  if (!order) throw bad("Order not found or already reviewed.", 409);
  res.json(order);
}));

/* ---------- Pages and errors ---------- */

app.get("/health", (req, res) => res.json({ status: "ok" }));

// Only index.html is served, so server source files are never exposed
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

app.use("/api", (req, res) => res.status(404).json({ error: "Not found." }));

app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Invalid request body." });
  const status = err.status || 500;
  if (status === 500) console.error(err);
  res.status(status).json({ error: status === 500 ? "Server error. Please try again." : err.message });
});

/* ---------- Demo data and startup ---------- */

async function seed() {
  const adminEmail = (process.env.ADMIN_EMAIL || "admin@demo.com").toLowerCase();
  const adminPassword = process.env.ADMIN_PASSWORD || "Admin@123";
  if (!(await User.findOne({ email: adminEmail }))) {
    await User.create({ name: "Demo Admin", email: adminEmail, passwordHash: await bcrypt.hash(adminPassword, 10), role: "admin" });
  }
  if (!(await User.findOne({ email: "customer@demo.com" }))) {
    await User.create({ name: "Demo Customer", email: "customer@demo.com", passwordHash: await bcrypt.hash("Customer@123", 10), role: "customer" });
  }
  if ((await Product.countDocuments()) === 0) {
    await Product.insertMany([
      { name: "Laptop Pro 15", category: "Laptops", description: "High performance laptop for developers", price: 89999, stock: 10, imageUrl: "https://images.unsplash.com/photo-1496181133206-80ce9b88a853?auto=format&fit=crop&w=600&q=70" },
      { name: "Wireless Mouse", category: "Accessories", description: "Ergonomic wireless mouse", price: 1499, stock: 50, imageUrl: "https://images.unsplash.com/photo-1527814050087-3793815479db?auto=format&fit=crop&w=600&q=70" },
      { name: "Mechanical Keyboard", category: "Accessories", description: "RGB mechanical keyboard", price: 3999, stock: 30, imageUrl: "https://images.unsplash.com/photo-1587829741301-dc798b83add3?auto=format&fit=crop&w=600&q=70" },
      { name: "Noise Cancelling Headphones", category: "Electronics", description: "Premium Bluetooth headphones", price: 6999, stock: 20, imageUrl: "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=600&q=70" },
      { name: "Smartphone X", category: "Mobiles", description: "Flagship smartphone with great camera", price: 59999, stock: 15, imageUrl: "https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?auto=format&fit=crop&w=600&q=70" },
      { name: "Bluetooth Speaker", category: "Electronics", description: "Portable wireless speaker", price: 2999, stock: 40, imageUrl: "https://images.unsplash.com/photo-1608043152269-423dbba4e7e1?auto=format&fit=crop&w=600&q=70" }
    ]);
  }
}

mongoose
  .connect(MONGODB_URI)
  .then(seed)
  .then(() => app.listen(PORT, () => console.log(`RoleCart running on port ${PORT}`)))
  .catch((err) => {
    console.error("Startup failed:", err.message);
    process.exit(1);
  });
