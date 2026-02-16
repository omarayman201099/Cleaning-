// server.js
/* eslint-disable no-console */
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// serve static/public files (admin UI, customer pages, uploaded images)
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// --- config ------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
const MONGO_URI = 'mongodb+srv://celaning:Boomyanyboom_109@cleaning.b4ruozt.mongodb.net/?appName=cleaning';
const JWT_SECRET = process.env.JWT_SECRET || 'cleaning-store-secret-key-2024';

// --- mongodb connection ------------------------------------------------------
mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => {
        console.error('Mongo connection failed', err);
        process.exit(1);
    });

// --- schemas & models --------------------------------------------------------
const adminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true },
    email:    { type: String, required: true, unique: true, trim: true, lowercase: true },
    password: { type: String, required: true },
    phone:    { type: String, trim: true },
    role:     { type: String, enum: ['superadmin','admin'], default: 'admin' },
    createdAt:{ type: Date, default: Date.now }
});
const Admin = mongoose.model('Admin', adminSchema);

const customerSchema = new mongoose.Schema({
    username: { type: String, required: true, trim: true },
    email:    { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    phone:    { type: String, trim: true },
    createdAt:{ type: Date, default: Date.now }
});
const Customer = mongoose.model('Customer', customerSchema);

const categorySchema = new mongoose.Schema({
    name:        { type: String, required: true, unique: true, trim: true },
    description: { type: String, default: '' },
    createdAt:   { type: Date, default: Date.now },
    updatedAt:   { type: Date }
});
const Category = mongoose.model('Category', categorySchema);

const productSchema = new mongoose.Schema({
    name:        { type: String, required: true, trim: true },
    description: { type: String, default: '' },
    price:       { type: Number, required: true },
    category:    { type: String, required: true },
    stock:       { type: Number, default: 0 },
    image:       { type: String, default: '/uploads/placeholder.svg' },
    createdAt:   { type: Date, default: Date.now },
    updatedAt:   { type: Date }
});
const Product = mongoose.model('Product', productSchema);

const orderSchema = new mongoose.Schema({
    customerName:  String,
    customerEmail: String,
    customerPhone: String,
    address:       String,
    items:         Array,
    totalAmount:   Number,
    status:        { type: String, default: 'pending' },
    createdAt:     { type: Date, default: Date.now },
    updatedAt:     { type: Date }
});
const Order = mongoose.model('Order', orderSchema);

// --- upload config -----------------------------------------------------------
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + Math.round(Math.random()*1E9) + path.extname(file.originalname))
});
const upload = multer({
    storage,
    limits: { fileSize: 5*1024*1024 },
    fileFilter: (req, file, cb) => {
        const allowed = /jpeg|jpg|png|gif|webp/;
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowed.test(ext) && allowed.test(file.mimetype)) cb(null, true);
        else cb(new Error('Only image files are allowed!'));
    }
});

// --- JWT helpers -------------------------------------------------------------
function generateToken(subject) {
    return jwt.sign(subject, JWT_SECRET, { expiresIn: '24h' });
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access denied. No token.' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        return res.status(403).json({ error: 'Invalid or expired token.' });
    }
}

// ===================== CUSTOMER ROUTES =======================================
app.post('/api/customers/register', async (req, res) => {
    try {
        const { username, email, password, phone } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'username, email and password are required' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: 'password must be at least 6 characters' });
        }
        const existing = await Customer.findOne({ email });
        if (existing) {
            return res.status(400).json({ error: 'email already in use' });
        }
        const hash = await bcrypt.hash(password, 10);
        const customer = new Customer({ username, email, password: hash, phone });
        await customer.save();
        res.status(201).json({ message: 'Customer registered successfully' });
    } catch (err) {
        console.error('register error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/customers/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'email and password required' });
        }
        const customer = await Customer.findOne({ email });
        if (!customer) {
            return res.status(401).json({ error: 'invalid credentials' });
        }
        const valid = await bcrypt.compare(password, customer.password);
        if (!valid) {
            return res.status(401).json({ error: 'invalid credentials' });
        }
        const token = generateToken({ id: customer._id, type: 'customer' });
        res.json({ token });
    } catch (err) {
        console.error('login error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/customers/me', authenticateToken, async (req, res) => {
    if (req.user.type !== 'customer') return res.status(403).json({ error: 'Not a customer token' });
    const customer = await Customer.findById(req.user.id).select('-password');
    if (!customer) return res.status(404).json({ error: 'Customer not found' });
    res.json(customer);
});

// ===================== ADMIN AUTH ===========================================
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password, phone } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'username, email, and password are required' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: 'password must be at least 6 characters' });
        }
        const count = await Admin.countDocuments();
        const role = count === 0 ? 'superadmin' : 'admin';
        const hash = await bcrypt.hash(password, 10);
        const admin = new Admin({ username, email, password: hash, role, phone });
        await admin.save();
        const token = generateToken({ id: admin._id, type: 'admin' });
        res.status(201).json({ token, admin: { id: admin._id, username, email, role } });
    } catch (err) {
        console.error(err);
        if (err.code === 11000) return res.status(400).json({ error: 'username/email exists' });
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'username and password required' });
        const admin = await Admin.findOne({ username });
        if (!admin) return res.status(401).json({ error: 'invalid credentials' });
        const ok = await bcrypt.compare(password, admin.password);
        if (!ok) return res.status(401).json({ error: 'invalid credentials' });
        const token = generateToken({ id: admin._id, type: 'admin' });
        res.json({ token, admin: { id: admin._id, username: admin.username, email: admin.email, phone: admin.phone, role: admin.role } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Login failed' });
    }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
    if (req.user.type !== 'admin') return res.status(403).json({ error: 'Not an admin token' });
    const admin = await Admin.findById(req.user.id).select('-password');
    if (!admin) return res.status(404).json({ error: 'Admin not found' });
    res.json(admin);
});

// ===================== CATEGORIES ROUTES =====================================
app.get('/api/categories', async (req, res) => { const cats = await Category.find(); res.json(cats); });
app.get('/api/categories/:id', async (req, res) => { const cat = await Category.findById(req.params.id); if (!cat) return res.status(404).json({ error: 'Category not found' }); res.json(cat); });
app.post('/api/categories', authenticateToken, async (req, res) => { const { name, description } = req.body; if (!name) return res.status(400).json({ error: 'name required' }); try { const cat = new Category({ name, description }); await cat.save(); res.status(201).json(cat); } catch (err) { console.error(err); if (err.code === 11000) return res.status(400).json({ error: 'Category exists' }); res.status(500).json({ error: 'Failed to create category' }); } });
app.put('/api/categories/:id', authenticateToken, async (req, res) => { const { name, description } = req.body; const cat = await Category.findById(req.params.id); if (!cat) return res.status(404).json({ error: 'Category not found' }); if (name) cat.name = name; if (description !== undefined) cat.description = description; cat.updatedAt = Date.now(); try { await cat.save(); res.json(cat); } catch (err) { console.error(err); res.status(500).json({ error: 'Update failed' }); } });
app.delete('/api/categories/:id', authenticateToken, async (req, res) => { const cat = await Category.findById(req.params.id); if (!cat) return res.status(404).json({ error: 'Category not found' }); const products = await Product.find({ category: cat.name }); if (products.length) return res.status(400).json({ error: 'Cannot delete category with products' }); await cat.deleteOne(); res.json({ message: 'Category deleted' }); });

// ===================== PRODUCTS ROUTES =====================================
app.get('/api/products', async (req, res) => {
    try {
        const { category, all } = req.query;
        // By default only return products with stock > 0 so out-of-stock items disappear from the store
        const baseFilter = { ...(category && category !== 'all' ? { category } : {}) };
        if (!all || all === 'false') {
            baseFilter.stock = { $gt: 0 };
        }
        const products = await Product.find(baseFilter);
        res.json(products);
    } catch (err) {
        console.error('GET /api/products error', err);
        res.status(500).json({ error: 'Failed to load products' });
    }
});
app.get('/api/products/:id', async (req, res) => { const p = await Product.findById(req.params.id); if (!p) return res.status(404).json({ error: 'Product not found' }); res.json(p); });
app.post('/api/products', authenticateToken, upload.single('image'), async (req, res) => { const { name, description, price, category, stock } = req.body; if (!name || !price || !category) return res.status(400).json({ error: 'name, price, category required' }); const prod = new Product({ name, description, price: parseFloat(price), category, stock: parseInt(stock) || 0, image: req.file ? '/uploads/' + req.file.filename : '/uploads/placeholder.svg' }); await prod.save(); res.status(201).json(prod); });
app.put('/api/products/:id', authenticateToken, upload.single('image'), async (req, res) => { const prod = await Product.findById(req.params.id); if (!prod) return res.status(404).json({ error: 'Product not found' }); const { name, description, price, category, stock } = req.body; if (name) prod.name = name; if (description !== undefined) prod.description = description; if (price) prod.price = parseFloat(price); if (category) prod.category = category; if (stock) prod.stock = parseInt(stock); if (req.file) { if (prod.image && prod.image !== '/uploads/placeholder.svg') { const oldPath = path.join(__dirname, prod.image); if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath); } prod.image = '/uploads/' + req.file.filename; } prod.updatedAt = Date.now(); await prod.save(); res.json(prod); });
app.delete('/api/products/:id', authenticateToken, async (req, res) => { const prod = await Product.findById(req.params.id); if (!prod) return res.status(404).json({ error: 'Product not found' }); if (prod.image && prod.image !== '/uploads/placeholder.svg') { const oldPath = path.join(__dirname, prod.image); if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath); } await prod.deleteOne(); res.json({ message: 'Product deleted' }); });

// ===================== ORDERS ROUTES =====================================
app.get('/api/orders', authenticateToken, async (req, res) => { const orders = await Order.find().sort({ createdAt: -1 }); res.json(orders); });
app.get('/api/orders/:id', authenticateToken, async (req, res) => { const order = await Order.findById(req.params.id); if (!order) return res.status(404).json({ error: 'Order not found' }); res.json(order); });
app.post('/api/orders', async (req, res) => {
    try {
        const { customerName, customerEmail, customerPhone, address, items, totalAmount } = req.body;
        if (!customerName || !customerEmail || !address) return res.status(400).json({ error: 'Missing customer info' });

        // Validate items and decrement stock atomically per item with rollback on failure
        const decremented = [];
        for (const it of items) {
            const prodId = it.id;
            const qty = Number(it.quantity) || 1;

            // Attempt to decrement stock only if enough stock exists
            const updated = await Product.findOneAndUpdate(
                { _id: prodId, stock: { $gte: qty } },
                { $inc: { stock: -qty } },
                { new: true }
            );

            if (!updated) {
                // Rollback previous decrements
                for (const d of decremented) {
                    await Product.findByIdAndUpdate(d.id, { $inc: { stock: d.qty } });
                }
                return res.status(400).json({ error: `Insufficient stock for product ${it.name || prodId}` });
            }

            decremented.push({ id: prodId, qty });
        }

        const order = new Order({ customerName, customerEmail, customerPhone, address, items, totalAmount });
        await order.save();
        res.status(201).json(order);
    } catch (err) {
        console.error('Create order error', err);
        res.status(500).json({ error: 'Failed to create order' });
    }
});
app.put('/api/orders/:id/status', authenticateToken, async (req, res) => { const { status } = req.body; const order = await Order.findById(req.params.id); if (!order) return res.status(404).json({ error: 'Order not found' }); order.status = status; order.updatedAt = Date.now(); await order.save(); res.json(order); });
app.delete('/api/orders/:id', authenticateToken, async (req, res) => { await Order.findByIdAndDelete(req.params.id); res.json({ message: 'Order deleted' }); });

// --- stats -------------------------------------------------------------------
app.get('/api/stats', authenticateToken, async (req, res) => {
    try {
        const totalProducts = await Product.countDocuments();
        const totalOrders = await Order.countDocuments();
        const totalAdmins = await Admin.countDocuments();

        const salesAgg = await Order.aggregate([{ $group: { _id: null, sum: { $sum: '$totalAmount' } } }]);
        const totalSales = salesAgg[0]?.sum || 0;

        // Aggregate orders by status (pending, confirmed, delivered, etc.)
        const statusAgg = await Order.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }]);
        const ordersByStatus = {};
        statusAgg.forEach(s => { ordersByStatus[s._id] = s.count; });

        res.json({ totalProducts, totalOrders, totalAdmins, totalSales, ordersByStatus });
    } catch (err) {
        console.error('GET /api/stats error', err);
        res.status(500).json({ error: 'Failed to load stats' });
    }
});

// --- page routes -------------------------------------------------------------
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/customer/index.html')));
app.get('/cart', (req, res) => res.sendFile(path.join(__dirname, 'public/customer/cart.html')));
app.get('/checkout', (req, res) => res.sendFile(path.join(__dirname, 'public/customer/checkout.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public/admin.html')));

// --- error handlers ----------------------------------------------------------
app.use((err, req, res, next) => { console.error('Error:', err.message); if (err.name === 'MulterError' && err.code === 'LIMIT_FILE_SIZE') { return res.status(400).json({ error: 'File too large. Max 5MB.' }); } res.status(500).json({ error: 'Something went wrong.' }); });
app.use((req, res) => { res.status(404).json({ error: 'Endpoint not found.' }); });

// --- start -------------------------------------------------------------------
app.listen(PORT, () => { console.log('='.repeat(50)); console.log(`🧹 Cleaning Products Store Backend`); console.log(`   Server running at: http://localhost:${PORT}`); console.log('='.repeat(50)); });