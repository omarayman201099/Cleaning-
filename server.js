/* eslint-disable no-console */
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ================= CONFIG =================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const MONGO_URI = process.env.MONGO_URI; // ⬅️ مهم جدًا
const JWT_SECRET = process.env.JWT_SECRET || 'cleaning-secret';

// ================= MONGODB CONNECTION =================
mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => {
        console.error('❌ MongoDB Connection Failed:', err.message);
        process.exit(1);
    });

// ================= SCHEMAS =================
const customerSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email:    { type: String, required: true, unique: true },
    password: { type: String, required: true },
    phone:    String,
    createdAt:{ type: Date, default: Date.now }
});

const orderSchema = new mongoose.Schema({
    customerName: String,
    customerEmail: String,
    address: String,
    items: Array,
    totalAmount: Number,
    status: { type: String, default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const Customer = mongoose.model('Customer', customerSchema);
const Order = mongoose.model('Order', orderSchema);

// ================= AUTH =================
app.post('/api/customers/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password)
            return res.status(400).json({ error: 'All fields required' });

        const existing = await Customer.findOne({ email });
        if (existing)
            return res.status(400).json({ error: 'Email already exists' });

        const hash = await bcrypt.hash(password, 10);

        await Customer.create({
            username,
            email,
            password: hash
        });

        res.status(201).json({ message: 'Registered successfully' });

    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/customers/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await Customer.findOne({ email });
        if (!user)
            return res.status(401).json({ error: 'Invalid credentials' });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid)
            return res.status(401).json({ error: 'Invalid credentials' });

        const token = jwt.sign(
            { id: user._id },
            JWT_SECRET,
            { expiresIn: '1d' }
        );

        res.json({ token });

    } catch {
        res.status(500).json({ error: 'Server error' });
    }
});

// ================= ORDERS =================
app.post('/api/orders', async (req, res) => {
    try {
        const { customerName, customerEmail, address, items, totalAmount } = req.body;

        const order = await Order.create({
            customerName,
            customerEmail,
            address,
            items,
            totalAmount
        });

        res.status(201).json(order);

    } catch (err) {
        res.status(500).json({ error: 'Failed to create order' });
    }
});

app.get('/api/orders', async (req, res) => {
    const orders = await Order.find().sort({ createdAt: -1 });
    res.json(orders);
});

// ================= HEALTH CHECK =================
app.get('/', (req, res) => {
    res.send('🚀 Cleaning Store Backend Running');
});

// ================= START SERVER =================
app.listen(PORT, () => {
    console.log('='.repeat(40));
    console.log(`🚀 Server running on port ${PORT}`);
    console.log('='.repeat(40));
});
