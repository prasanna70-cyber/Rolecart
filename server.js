const path = require("path");
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const PORT = process.env.PORT || 10000;
const clean = (v) => String(v || "").trim().replace(/^["']+|["']+$/g, "");
const MONGODB_URI = clean(process.env.MONGODB_URI);
const JWT_SECRET = clean(process.env.JWT_SECRET) || "RolecartSuperSecretKey2026";

const app = express();
app.use(express.json({ limit: "100kb" }));

// ===== DEMO MEMORY DATA (No DB needed) =====
let USE_MEMORY = false;
const mem = {
  users: [
    { _id: "admin1", name: "Demo Admin", email: "admin@demo.com", passwordHash: bcrypt.hashSync("Admin@123",10), role: "admin" },
    { _id: "cust1", name: "Demo Customer", email: "customer@demo.com", passwordHash: bcrypt.hashSync("Customer@123",10), role: "customer" }
  ],
  products: [
    { _id: "p1", name: "Laptop Pro 15", category: "Laptops", description: "High performance laptop", price: 89999, stock: 10, imageUrl: "https://images.unsplash.com/photo-1496181133206-80ce9b88a853?w=600", createdAt: new Date() },
    { _id: "p2", name: "Wireless Mouse", category: "Accessories", description: "Ergonomic mouse", price: 1499, stock: 50, imageUrl: "https://images.unsplash.com/photo-1527814050087-3793815479db?w=600", createdAt: new Date() },
    { _id: "p3", name: "Mechanical Keyboard", category: "Accessories", description: "RGB keyboard", price: 3999, stock: 30, imageUrl: "https://images.unsplash.com/photo-1587829741301-dc798b83add3?w=600", createdAt: new Date() }
  ],
  orders: []
};

// ===== Helpers =====
const wrap = (fn) => (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next);
const bad = (msg,status=400) => Object.assign(new Error(msg),{status});
function signToken(u){ return jwt.sign({ id: String(u._id), role: u.role, name: u.name }, JWT_SECRET, {expiresIn:"8h"}); }
function publicUser(u){ return { id: String(u._id), name: u.name, email: u.email, role: u.role }; }
function auth(req,res,next){
  const token = (req.headers.authorization||"").replace("Bearer ","");
  if(!token) return res.status(401).json({error:"Please log in first."});
  try{ const p=jwt.verify(token,JWT_SECRET); req.user={id:p.id, role:p.role, name:p.name}; next(); } catch{ res.status(401).json({error:"Invalid session"}); }
}
const requireRole = (...roles)=>(req,res,next)=> roles.includes(req.user.role) ? next() : res.status(403).json({error:"Access denied"});

// ===== Auth =====
app.post("/api/auth/register", wrap(async(req,res)=>{
  const name=String(req.body.name||"").trim();
  const email=String(req.body.email||"").toLowerCase();
  const password=String(req.body.password||"");
  if(!name) throw bad("Name required"); if(password.length<6) throw bad("Password min 6");
  if(USE_MEMORY){
    if(mem.users.find(u=>u.email===email)) throw bad("Email exists",409);
    const u={ _id: Date.now().toString(), name, email, passwordHash: await bcrypt.hash(password,10), role:"customer"};
    mem.users.push(u); return res.status(201).json({ token: signToken(u), user: publicUser(u) });
  }
  const user = await User.create({ name, email, passwordHash: await bcrypt.hash(password,10), role:"customer" });
  res.status(201).json({ token: signToken(user), user: publicUser(user) });
}));

app.post("/api/auth/login", wrap(async(req,res)=>{
  const email=String(req.body.email||"").toLowerCase();
  const password=String(req.body.password||"");
  let user = USE_MEMORY ? mem.users.find(u=>u.email===email) : await User.findOne({email});
  if(!user || !(await bcrypt.compare(password, user.passwordHash))) throw bad("Incorrect email or password",401);
  res.json({ token: signToken(user), user: publicUser(user) });
}));

app.get("/api/auth/me", auth, wrap(async(req,res)=>{
  let user = USE_MEMORY ? mem.users.find(u=>u._id===req.user.id || u.email===req.user.id) : await User.findById(req.user.id);
  if(!user) throw bad("Account not found",401);
  res.json({ user: publicUser(user) });
}));

// ===== Products =====
app.get("/api/products", wrap(async(req,res)=>{ res.json(USE_MEMORY ? mem.products : await Product.find().sort({createdAt:-1})); }));
app.post("/api/products", auth, requireRole("admin"), wrap(async(req,res)=>{
  if(USE_MEMORY){ const p={ _id: Date.now().toString(), ...req.body, createdAt: new Date()}; mem.products.push(p); return res.status(201).json(p); }
  res.status(201).json(await Product.create(req.body));
}));
app.put("/api/products/:id", auth, requireRole("admin"), wrap(async(req,res)=>{
  if(USE_MEMORY){ const i=mem.products.findIndex(p=>p._id===req.params.id); if(i===-1) throw bad("Not found",404); mem.products[i]={...mem.products[i], ...req.body}; return res.json(mem.products[i]); }
  const p=await Product.findByIdAndUpdate(req.params.id, req.body, {new:true}); if(!p) throw bad("Not found",404); res.json(p);
}));
app.delete("/api/products/:id", auth, requireRole("admin"), wrap(async(req,res)=>{
  if(USE_MEMORY){ mem.products=mem.products.filter(p=>p._id!==req.params.id); return res.json({deleted:true}); }
  await Product.findByIdAndDelete(req.params.id); res.json({deleted:true});
}));

// ===== Orders =====
app.post("/api/orders", auth, requireRole("customer"), wrap(async(req,res)=>{
  const items=req.body.items||[]; if(!items.length) throw bad("Cart empty");
  if(USE_MEMORY){ const o={ _id: Date.now().toString(), user: req.user.id, items, total: items.reduce((s,i)=> s + (i.price*i.quantity),0), status:"PENDING", createdAt: new Date()}; mem.orders.push(o); return res.status(201).json(o); }
  const order=await Order.create({ user: req.user.id, items, total: req.body.total||0, status:"PENDING" }); res.status(201).json(order);
}));
app.get("/api/orders/mine", auth, requireRole("customer"), wrap(async(req,res)=>{ res.json(USE_MEMORY ? mem.orders.filter(o=>o.user===req.user.id) : await Order.find({user:req.user.id}).sort({createdAt:-1})); }));
app.get("/api/orders", auth, requireRole("admin"), wrap(async(req,res)=>{ res.json(USE_MEMORY ? mem.orders : await Order.find().sort({createdAt:-1})); }));
app.patch("/api/orders/:id/approve", auth, requireRole("admin"), wrap(async(req,res)=>{ if(USE_MEMORY){ const o=mem.orders.find(o=>o._id===req.params.id); if(o) o.status="APPROVED"; return res.json(o); } const o=await Order.findByIdAndUpdate(req.params.id,{status:"APPROVED"},{new:true}); res.json(o); }));
app.patch("/api/orders/:id/reject", auth, requireRole("admin"), wrap(async(req,res)=>{ if(USE_MEMORY){ const o=mem.orders.find(o=>o._id===req.params.id); if(o) o.status="REJECTED"; return res.json(o); } const o=await Order.findByIdAndUpdate(req.params.id,{status:"REJECTED"},{new:true}); res.json(o); }));

app.get("/health", (req,res)=> res.json({ status:"ok", mode: USE_MEMORY ? "demo-memory-no-db" : "mongodb" }));
app.get("/", (req,res)=> res.sendFile(path.join(__dirname,"index.html")));
app.use((err,req,res,next)=> res.status(err.status||500).json({ error: err.message||"Server error" }));

// ===== DB Models (only if DB available) =====
const userSchema = new mongoose.Schema({ name:String, email:{type:String,unique:true}, passwordHash:String, role:{type:String,enum:["customer","admin"],default:"customer"}},{timestamps:true});
const productSchema = new mongoose.Schema({ name:String, description:String, category:String, price:Number, stock:Number, imageUrl:String},{timestamps:true});
const orderSchema = new mongoose.Schema({ user:{type:mongoose.Schema.Types.ObjectId, ref:"User"}, items:Array, total:Number, status:{type:String,default:"PENDING"}},{timestamps:true});
const User = mongoose.model("User", userSchema);
const Product = mongoose.model("Product", productSchema);
const Order = mongoose.model("Order", orderSchema);

async function start(){
  if(!MONGODB_URI || !/^mongodb(\+srv)?:\/\//.test(MONGODB_URI)){
    console.log("No valid MONGODB_URI - Starting in DEMO MEMORY MODE - App will be LIVE");
    USE_MEMORY=true;
    app.listen(PORT, ()=> console.log(`RoleCart running on ${PORT} - DEMO MODE LIVE`));
    return;
  }
  try{
    await mongoose.connect(MONGODB_URI);
    console.log("MongoDB Connected");
    app.listen(PORT, ()=> console.log(`RoleCart running on ${PORT}`));
  }catch(e){
    console.log("MongoDB auth failed:", e.message, "- Switching to DEMO MEMORY MODE - App LIVE");
    USE_MEMORY=true;
    app.listen(PORT, ()=> console.log(`RoleCart running on ${PORT} - DEMO MODE LIVE`));
  }
}
start();
