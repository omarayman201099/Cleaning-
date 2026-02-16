// ===================== ADMIN DASHBOARD JS =====================
// Complete admin dashboard with JWT authentication and categories management

const API_URL = 'http://localhost:3000/api';

// State management
let isLoggedIn = false;
let currentUser = null;
let authToken = null;
let categories = [];
let statsIntervalId = null;
let currentViewedOrder = null;

// ==================== Authentication ====================

// Get auth token from localStorage
function getAuthToken() {
    return localStorage.getItem('adminToken');
}

// Save auth token
function saveAuthToken(token) {
    localStorage.setItem('adminToken', token);
}

// Clear auth token
function clearAuthToken() {
    localStorage.removeItem('adminToken');
}

// Login form handler
document.getElementById('login-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const errorElement = document.getElementById('login-error');
    
    try {
        const response = await fetch(`${API_URL}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            isLoggedIn = true;
            currentUser = data.admin;
            authToken = data.token;
            
            // Save token and user
            saveAuthToken(authToken);
            localStorage.setItem('adminUser', JSON.stringify(data.admin));
            
            // Clear error message
            errorElement.textContent = '';
            
            showDashboard();
        } else {
            errorElement.textContent = data.error || 'Login failed';
        }
    } catch (error) {
        errorElement.textContent = 'An error occurred. Please try again.';
        console.error('Login error:', error);
    }
});

// Logout handler
document.getElementById('logout-btn')?.addEventListener('click', () => {
    isLoggedIn = false;
    currentUser = null;
    authToken = null;
    clearAuthToken();
    localStorage.removeItem('adminUser');
    stopStatsPolling();
    showLogin();
});

function startStatsPolling() {
    if (statsIntervalId) return;
    // initial load
    loadStats();
    // poll every 10 seconds
    statsIntervalId = setInterval(() => {
        loadStats();
    }, 10000);
}

function stopStatsPolling() {
    if (!statsIntervalId) return;
    clearInterval(statsIntervalId);
    statsIntervalId = null;
}

// Check for existing session
function checkAuth() {
    const savedToken = getAuthToken();
    const savedUser = localStorage.getItem('adminUser');
    
    if (savedToken && savedUser) {
        authToken = savedToken;
        currentUser = JSON.parse(savedUser);
        
        // Verify token is still valid
        fetch(`${API_URL}/auth/me`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        }).then(res => {
            if (res.ok) {
                isLoggedIn = true;
                showDashboard();
            } else {
                // Token expired, show login
                showLogin();
            }
        }).catch(() => {
            showLogin();
        });
    } else {
        showLogin();
    }
}

// ==================== UI Functions ====================

function showLogin() {
    document.getElementById('login-section').classList.remove('hidden');
    document.getElementById('dashboard-section').classList.add('hidden');
}

function showDashboard() {
    document.getElementById('login-section').classList.add('hidden');
    document.getElementById('dashboard-section').classList.remove('hidden');
    
    // Show admin info
    const adminInfo = document.getElementById('admin-info');
    if (adminInfo && currentUser) {
        adminInfo.textContent = `${currentUser.username} (${currentUser.role})`;
    }
    
    loadCategories();
    startStatsPolling();
    loadProducts();
    loadOrders();
}

// Tab navigation
document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        // Update active button
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        // Show corresponding tab
        const tabId = btn.dataset.tab + '-tab';
        document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
        document.getElementById(tabId)?.classList.add('active');
        
        // Reset form when switching to add product tab
        if (btn.dataset.tab === 'add-product') {
            resetProductForm();
        }
    });
});

// ==================== Categories ====================

async function loadCategories() {
    try {
        const response = await fetch(`${API_URL}/categories`);
        if (!response.ok) {
            throw new Error('Failed to load categories');
        }
        categories = await response.json();
        
        // Populate category dropdowns
        populateCategoryDropdowns();
        
        // Render categories in the categories tab
        renderCategories();
    } catch (error) {
        console.error('Failed to load categories:', error);
        showToast('Failed to load categories', 'error');
    }
}

function populateCategoryDropdowns() {
    const productCategory = document.getElementById('product-category');
    const editProductCategory = document.getElementById('edit-product-category');
    
    const options = '<option value="">Select Category</option>' + 
        categories.map(cat => `<option value="${cat.name}">${cat.name}</option>`).join('');
    
    if (productCategory) {
        productCategory.innerHTML = options;
    }
    if (editProductCategory) {
        editProductCategory.innerHTML = options;
    }
}

function renderCategories() {
    const categoriesList = document.getElementById('categories-list');
    if (!categoriesList) return;
    
    if (categories.length === 0) {
        categoriesList.innerHTML = '<p class="loading">No categories found</p>';
        return;
    }
    
    categoriesList.innerHTML = categories.map(category => `
        <div class="category-card">
            <div class="category-card-body">
                <h3>${category.name}</h3>
                <p class="description">${category.description || 'No description'}</p>
                <div class="category-actions">
                    <button class="btn btn-primary btn-small" onclick="editCategory('${category._id}')">Edit</button>
                    <button class="btn btn-danger btn-small" onclick="deleteCategory('${category._id}')">Delete</button>
                </div>
            </div>
        </div>
    `).join('');
}

// Add category button
document.getElementById('add-category-btn')?.addEventListener('click', () => {
    document.getElementById('category-modal-title').textContent = 'Add New Category';
    document.getElementById('category-id').value = '';
    document.getElementById('category-form').reset();
    document.getElementById('category-modal').classList.remove('hidden');
});

// Category form handler
document.getElementById('category-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const categoryId = document.getElementById('category-id').value;
    const name = document.getElementById('category-name').value;
    const description = document.getElementById('category-description').value;
    
    const method = categoryId ? 'PUT' : 'POST';
    const url = categoryId ? `${API_URL}/categories/${categoryId}` : `${API_URL}/categories`;
    
    try {
        const response = await fetch(url, {
            method,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${getAuthToken()}`
            },
            body: JSON.stringify({ name, description })
        });
        
        if (response.ok) {
            showToast('Category saved successfully!', 'success');
            document.getElementById('category-modal').classList.add('hidden');
            loadCategories();
        } else {
            const data = await response.json();
            showToast(data.error || 'Failed to save category', 'error');
        }
    } catch (error) {
        showToast('An error occurred', 'error');
        console.error('Category save error:', error);
    }
});

// Edit category
async function editCategory(categoryId) {
    const category = categories.find(c => c.id === categoryId);
    if (!category) return;
    
    document.getElementById('category-modal-title').textContent = 'Edit Category';
    document.getElementById('category-id').value = category._id;
    document.getElementById('category-name').value = category.name;
    document.getElementById('category-description').value = category.description || '';
    document.getElementById('category-modal').classList.remove('hidden');
}

// Delete category
function deleteCategory(categoryId) {
    document.getElementById('delete-item-id').value = categoryId;
    document.getElementById('delete-item-type').value = 'category';
    document.getElementById('delete-modal').classList.remove('hidden');
}

// Close category modal
document.getElementById('close-category-modal')?.addEventListener('click', () => {
    document.getElementById('category-modal').classList.add('hidden');
});

// ==================== Stats ====================

async function loadStats() {
    try {
        const response = await fetch(`${API_URL}/stats`, {
            headers: {
                'Authorization': `Bearer ${getAuthToken()}`
            }
        });
        
        if (!response.ok) {
            if (response.status === 401 || response.status === 403) {
                showLogin();
                return;
            }
            throw new Error('Failed to load stats');
        }
        
        const stats = await response.json();
        
        document.getElementById('stat-products').textContent = stats.totalProducts || 0;
        document.getElementById('stat-orders').textContent = stats.totalOrders || 0;
        const salesEl = document.getElementById('stat-sales');
        const totalSales = typeof stats.totalSales === 'number' ? stats.totalSales : 0;
        salesEl.textContent = `$${totalSales.toFixed(2)}`;

        const pendingCount = Number(stats.ordersByStatus?.pending) || 0;
        const pendingEl = document.getElementById('stat-pending');
        pendingEl.textContent = pendingCount;
        if (pendingCount > 0) pendingEl.classList.add('pending');
        else pendingEl.classList.remove('pending');
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

// ==================== Products ====================

async function loadProducts() {
    try {
        // Request all products for admin view (including out-of-stock)
        const response = await fetch(`${API_URL}/products?all=true`);
        if (!response.ok) {
            throw new Error('Failed to load products');
        }
        const products = await response.json();
        
        const productsList = document.getElementById('products-list');
        
        if (products.length === 0) {
            productsList.innerHTML = '<p class="loading">No products found</p>';
            return;
        }
        
        productsList.innerHTML = products.map(product => `
            <div class="product-card">
                <img src="${product.image}" alt="${product.name}" onerror="this.style.display='none'">
                <div class="product-card-body">
                    <h3>${product.name}</h3>
                    <p class="description">${product.description}</p>
                    <p class="price">$${parseFloat(product.price).toFixed(2)}</p>
                    <p class="stock">Stock: ${product.stock}</p>
                    <span class="category">${product.category}</span>
                    <div class="product-actions">
                        <button class="btn btn-primary btn-small" onclick="editProduct('${product._id}')">Edit</button>
                        <button class="btn btn-danger btn-small" onclick="deleteProduct('${product._id}')">Delete</button>
                    </div>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to load products:', error);
        showToast('Failed to load products', 'error');
    }
}

// Product form handler
document.getElementById('product-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const formData = new FormData();
    formData.append('name', document.getElementById('product-name').value);
    formData.append('description', document.getElementById('product-description').value);
    formData.append('price', document.getElementById('product-price').value);
    formData.append('stock', document.getElementById('product-stock').value);
    formData.append('category', document.getElementById('product-category').value);
    
    const imageFile = document.getElementById('product-image').files[0];
    if (imageFile) {
        formData.append('image', imageFile);
    }
    
    try {
        const response = await fetch(`${API_URL}/products`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${getAuthToken()}`
            },
            body: formData
        });
        
        if (response.ok) {
            showToast('Product added successfully!', 'success');
            resetProductForm();
            loadProducts();
            loadStats();
            
            // Switch to products tab
            document.querySelector('[data-tab="products"]').click();
        } else {
            const data = await response.json();
            showToast(data.error || 'Failed to add product', 'error');
        }
    } catch (error) {
        showToast('An error occurred', 'error');
        console.error('Product add error:', error);
    }
});

function resetProductForm() {
    document.getElementById('product-form').reset();
    document.getElementById('product-id').value = '';
    document.getElementById('product-form-title').textContent = 'Add New Product';
    document.getElementById('submit-product-btn').textContent = 'Add Product';
    document.getElementById('image-preview').innerHTML = '';
}

// Image preview for add form
document.getElementById('product-image')?.addEventListener('change', function() {
    const preview = document.getElementById('image-preview');
    if (this.files && this.files[0]) {
        const reader = new FileReader();
        reader.onload = function(e) {
            preview.innerHTML = `<img src="${e.target.result}" alt="Preview">`;
        };
        reader.readAsDataURL(this.files[0]);
    }
});

// ==================== Edit Product ====================

async function editProduct(productId) {
    try {
        const response = await fetch(`${API_URL}/products/${productId}`);
        if (!response.ok) {
            throw new Error('Failed to load product');
        }
        const product = await response.json();
        
        document.getElementById('edit-product-id').value = product._id;
        document.getElementById('edit-product-name').value = product.name;
        document.getElementById('edit-product-description').value = product.description;
        document.getElementById('edit-product-price').value = product.price;
        document.getElementById('edit-product-stock').value = product.stock;
        
        // Wait for categories to load, then set the category
        setTimeout(() => {
            document.getElementById('edit-product-category').value = product.category;
        }, 100);
        
        // Show current image
        const preview = document.getElementById('edit-image-preview');
        preview.innerHTML = `<img src="${product.image}" alt="Current Image" onerror="this.style.display='none'">`;
        
        document.getElementById('edit-modal').classList.remove('hidden');
    } catch (error) {
        showToast('Failed to load product', 'error');
        console.error('Edit product error:', error);
    }
}

// Edit product form handler
document.getElementById('edit-product-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const productId = document.getElementById('edit-product-id').value;
    const formData = new FormData();
    formData.append('name', document.getElementById('edit-product-name').value);
    formData.append('description', document.getElementById('edit-product-description').value);
    formData.append('price', document.getElementById('edit-product-price').value);
    formData.append('stock', document.getElementById('edit-product-stock').value);
    formData.append('category', document.getElementById('edit-product-category').value);
    
    const imageFile = document.getElementById('edit-product-image').files[0];
    if (imageFile) {
        formData.append('image', imageFile);
    }
    
    try {
        const response = await fetch(`${API_URL}/products/${productId}`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${getAuthToken()}`
            },
            body: formData
        });
        
        if (response.ok) {
            showToast('Product updated successfully!', 'success');
            closeEditModal();
            loadProducts();
            loadStats();
        } else {
            const data = await response.json();
            showToast(data.error || 'Failed to update product', 'error');
        }
    } catch (error) {
        showToast('An error occurred', 'error');
        console.error('Product update error:', error);
    }
});

// Close edit modal
document.getElementById('close-modal')?.addEventListener('click', closeEditModal);

function closeEditModal() {
    document.getElementById('edit-modal').classList.add('hidden');
    document.getElementById('edit-product-form').reset();
}

// Image preview for edit form
document.getElementById('edit-product-image')?.addEventListener('change', function() {
    const preview = document.getElementById('edit-image-preview');
    if (this.files && this.files[0]) {
        const reader = new FileReader();
        reader.onload = function(e) {
            preview.innerHTML = `<img src="${e.target.result}" alt="Preview">`;
        };
        reader.readAsDataURL(this.files[0]);
    }
});

// ==================== Delete Product ====================

function deleteProduct(productId) {
    document.getElementById('delete-item-id').value = productId;
    document.getElementById('delete-item-type').value = 'product';
    document.getElementById('delete-modal').classList.remove('hidden');
}

// ==================== Delete Handler ====================

document.getElementById('close-delete-modal')?.addEventListener('click', () => {
    document.getElementById('delete-modal').classList.add('hidden');
});

document.getElementById('cancel-delete-btn')?.addEventListener('click', () => {
    document.getElementById('delete-modal').classList.add('hidden');
});

document.getElementById('confirm-delete-btn')?.addEventListener('click', async () => {
    const itemId = document.getElementById('delete-item-id').value;
    const itemType = document.getElementById('delete-item-type').value;
    
    const endpoint = itemType === 'product' ? 'products' : 'categories';
    
    try {
        const response = await fetch(`${API_URL}/${endpoint}/${itemId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${getAuthToken()}`
            }
        });
        
        if (response.ok) {
            showToast(`${itemType} deleted successfully!`, 'success');
            document.getElementById('delete-modal').classList.add('hidden');
            
            if (itemType === 'product') {
                loadProducts();
            } else {
                loadCategories();
            }
            loadStats();
        } else {
            const data = await response.json();
            showToast(data.error || `Failed to delete ${itemType}`, 'error');
        }
    } catch (error) {
        showToast('An error occurred', 'error');
        console.error('Delete error:', error);
    }
});

// ==================== Orders ====================

async function loadOrders() {
    try {
        const response = await fetch(`${API_URL}/orders`, {
            headers: {
                'Authorization': `Bearer ${getAuthToken()}`
            }
        });
        
        if (!response.ok) {
            if (response.status === 401 || response.status === 403) {
                showLogin();
                return;
            }
            throw new Error('Failed to load orders');
        }
        
        const orders = await response.json();
        
        const tbody = document.getElementById('orders-tbody');
        
        if (orders.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="loading">No orders found</td></tr>';
            return;
        }
        
        tbody.innerHTML = orders.map(order => `
            <tr>
                <td>${order._id.toString().substring(0, 8)}</td>
                <td>
                    <strong>${order.customerName}</strong><br>
                    <small>${order.customerEmail}</small>
                </td>
                <td>${order.items ? order.items.length : 0} items</td>
                <td>$${parseFloat(order.totalAmount).toFixed(2)}</td>
                <td><span class="status-badge status-${order.status}">${order.status}</span></td>
                <td>${new Date(order.createdAt).toLocaleDateString()}</td>
                <td>
                    <button class="btn btn-secondary btn-small" onclick="viewOrder('${order._id}')">View</button>
                    <button class="btn btn-primary btn-small" onclick="updateOrderStatus('${order._id}')">Update</button>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Failed to load orders:', error);
        showToast('Failed to load orders', 'error');
    }
}

function updateOrderStatus(orderId) {
    document.getElementById('status-order-id').value = orderId;
    document.getElementById('status-modal').classList.remove('hidden');
}

document.getElementById('close-status-modal')?.addEventListener('click', () => {
    document.getElementById('status-modal').classList.add('hidden');
});

// View order modal handling
async function viewOrder(orderId) {
        try {
                const res = await fetch(`${API_URL}/orders/${orderId}`, {
                        headers: { 'Authorization': `Bearer ${getAuthToken()}` }
                });
                if (!res.ok) return showToast('Failed to load order', 'error');
                const order = await res.json();
                currentViewedOrder = order;

                const el = document.getElementById('view-modal');
                el.querySelector('.order-id').textContent = order._id.toString();
                el.querySelector('.order-customer').innerHTML = `<strong>${order.customerName}</strong><br><small>${order.customerEmail}</small><br><small>${order.customerPhone || ''}</small>`;
                el.querySelector('.order-address').textContent = order.address || '';
                el.querySelector('.order-status').textContent = order.status || '';
                el.querySelector('.order-date').textContent = new Date(order.createdAt).toLocaleString();
                el.querySelector('.order-total').textContent = `$${parseFloat(order.totalAmount || 0).toFixed(2)}`;

                const itemsList = el.querySelector('.order-items');
                itemsList.innerHTML = '';
                (order.items || []).forEach(it => {
                        const li = document.createElement('div');
                        li.className = 'order-item';
                        li.innerHTML = `${it.name || ''} x ${it.quantity || 1} — $${parseFloat(it.price || 0).toFixed(2)}`;
                        itemsList.appendChild(li);
                });

                el.classList.remove('hidden');
        } catch (err) {
                console.error('viewOrder error', err);
                showToast('Failed to load order', 'error');
        }
}

document.getElementById('close-view-modal')?.addEventListener('click', () => {
        document.getElementById('view-modal').classList.add('hidden');
});

document.getElementById('close-view-modal-btn')?.addEventListener('click', () => {
    document.getElementById('view-modal').classList.add('hidden');
});

function printInvoice() {
        if (!currentViewedOrder) return showToast('No order selected', 'error');
        const o = currentViewedOrder;
        const win = window.open('', '_blank', 'width=800,height=900');
        const itemsHtml = (o.items || []).map(it => `<tr><td>${it.name || ''}</td><td>${it.quantity||1}</td><td>$${parseFloat(it.price||0).toFixed(2)}</td><td>$${(parseFloat(it.price||0)* (it.quantity||1)).toFixed(2)}</td></tr>`).join('');
        const html = `
        <html>
        <head>
            <title>Invoice - ${o._id}</title>
            <style>
                body{font-family: Arial, Helvetica, sans-serif;padding:20px}
                h1{color:#333}
                table{width:100%;border-collapse:collapse;margin-top:10px}
                th,td{border:1px solid #ccc;padding:8px;text-align:left}
                .total{font-weight:bold}
            </style>
        </head>
        <body>
            <h1>Invoice</h1>
            <p><strong>Order:</strong> ${o._id}</p>
            <p><strong>Date:</strong> ${new Date(o.createdAt).toLocaleString()}</p>
            <h3>Customer</h3>
            <p>${o.customerName}<br>${o.customerEmail}<br>${o.customerPhone || ''}<br>${o.address || ''}</p>
            <h3>Items</h3>
            <table>
                <thead><tr><th>Product</th><th>Qty</th><th>Unit</th><th>Line</th></tr></thead>
                <tbody>
                    ${itemsHtml}
                </tbody>
            </table>
            <p class="total">Total: $${parseFloat(o.totalAmount||0).toFixed(2)}</p>
            <p>Thank you for your purchase.</p>
        </body>
        </html>`;
        win.document.write(html);
        win.document.close();
        win.focus();
        setTimeout(() => { win.print(); }, 500);
}

document.getElementById('status-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const orderId = document.getElementById('status-order-id').value;
    const status = document.getElementById('order-status').value;
    
    try {
        const response = await fetch(`${API_URL}/orders/${orderId}/status`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${getAuthToken()}`
            },
            body: JSON.stringify({ status })
        });
        
        if (response.ok) {
            showToast('Order status updated!', 'success');
            document.getElementById('status-modal').classList.add('hidden');
            loadOrders();
            loadStats();
        } else {
            const data = await response.json();
            showToast(data.error || 'Failed to update status', 'error');
        }
    } catch (error) {
        showToast('An error occurred', 'error');
        console.error('Status update error:', error);
    }
});

// ==================== Toast Notifications ====================

function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 3000);
}

// ==================== Initialize ====================

document.addEventListener('DOMContentLoaded', checkAuth);