# Cleaning Products Store - Backend System

A complete backend system for a cleaning products store with Node.js, Express, and an admin dashboard.

## Features

### Backend
- Node.js + Express REST API
- Customer & admin authentication (register/login) backed by MongoDB
- Data stored in MongoDB collections instead of JSON files
- Image upload to local folder
- Error handling

### REST API Endpoints

#### Products
- `GET /api/products` - Get all products
- `GET /api/products/:id` - Get single product
- `POST /api/products` - Add new product (with image upload)
- `PUT /api/products/:id` - Update product
- `DELETE /api/products/:id` - Delete product

#### Orders
- `GET /api/orders` - Get all orders
- `POST /api/orders` - Create new order
- `PUT /api/orders/:id/status` - Update order status (pending, confirmed, delivered)

#### Customers
- `POST /api/customers/register` - Register new customer (optional phone number)
- `POST /api/customers/login` - Login customer (returns JWT)
- `GET /api/customers/me` - Get current customer info (protected)

#### Admin
- `POST /api/auth/login` - Admin login

#### Stats
- `GET /api/stats` - Get dashboard statistics

## Admin Dashboard

- Login page for admin
- Add/Edit/Delete products with image upload
- View all products
- View all orders and update their status
- Display stats: total products, total orders, total sales, pending orders

## Project Structure

```
cleaning-backend/
├── data/                # legacy JSON files (no longer used)
│   ├── products.json
│   ├── orders.json
│   └── admins.json
├── public/
│   ├── admin.html
│   ├── admin.css
│   └── admin.js
├── uploads/
├── index.js
├── package.json
└── README.md
```

## Installation & Running

1. Make sure you have MongoDB running locally (e.g. start the `mongod` service or use MongoDB Desktop/Compass).

2. Install dependencies:
```
npm install
```

3. Start the server:
```
npm start
```

The app will connect to `mongodb://localhost:27017/CleaningStore` by default; you can override with the `MONGO_URI` environment variable.

3. Open the admin dashboard:
```
http://localhost:3000/admin
```

## Default Admin Credentials

- Username: `admin`
- Password: `admin123`

## API Examples

### Get all products
```
bash
curl http://localhost:3000/api/products
```

### Add a product (with curl)
```
bash
curl -X POST -F "name=Product Name" -F "description=Description" -F "price=9.99" -F "stock=100" -F "category=cleaners" -F "image=@image.jpg" http://localhost:3000/api/products
```

### Create an order
```
bash
curl -X POST -H "Content-Type: application/json" -d '{"customerName":"John Doe","customerEmail":"john@example.com","customerPhone":"1234567890","address":"123 Main St","items":[{"id":"1","name":"Product","price":9.99,"quantity":2}],"totalAmount":19.98}' http://localhost:3000/api/orders
```

### Update order status
```
bash
curl -X PUT -H "Content-Type: application/json" -d '{"status":"confirmed"}' http://localhost:3000/api/orders/:id/status
```

## Technologies Used

- Node.js
- Express.js
- Multer (file uploads)
- CORS
- UUID (for generating IDs)

## License

Free to use and modify.
