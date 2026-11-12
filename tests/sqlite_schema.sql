-- Test-only copy of schema.sql for SQLite (so the automatic tests can run without a MySQL server).
-- The real database is MySQL. See database/schema.sql.
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer' CHECK (role IN ('customer','admin')),
  phone TEXT, address TEXT, city TEXT, province TEXT, is_active INTEGER NOT NULL DEFAULT 1, email_verified INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE categories (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE);
CREATE TABLE plants (
  id INTEGER PRIMARY KEY AUTOINCREMENT, category_id INTEGER NOT NULL REFERENCES categories(id), name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '', price DECIMAL(10,2) NOT NULL CHECK (price > 0 AND price <= 100000),
  stock_quantity INTEGER NOT NULL DEFAULT 0 CHECK (stock_quantity >= 0 AND stock_quantity <= 9999),
  image_path TEXT, is_available INTEGER NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending','Confirmed','Processing','Ready for Pickup','Completed','Cancelled')),
  fulfillment TEXT NOT NULL CHECK (fulfillment IN ('pickup','delivery')),
  delivery_fee DECIMAL(10,2) NOT NULL DEFAULT 0 CHECK (delivery_fee >= 0), total_amount DECIMAL(10,2) NOT NULL CHECK (total_amount >= 0),
  contact_name TEXT NOT NULL, contact_phone TEXT NOT NULL, address TEXT NOT NULL, city TEXT NOT NULL, province TEXT NOT NULL,
  notes TEXT, stock_deducted INTEGER NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  plant_id INTEGER NOT NULL REFERENCES plants(id), plant_name TEXT NOT NULL, unit_price DECIMAL(10,2) NOT NULL CHECK (unit_price > 0),
  quantity INTEGER NOT NULL CHECK (quantity >= 1), UNIQUE (order_id, plant_id));
CREATE TABLE stock_movements (
  id INTEGER PRIMARY KEY AUTOINCREMENT, plant_id INTEGER NOT NULL REFERENCES plants(id) ON DELETE CASCADE,
  movement_type TEXT NOT NULL CHECK (movement_type IN ('initial_stock','order_placed','order_cancelled','restock','damaged_lost','correction')),
  quantity_change INTEGER NOT NULL CHECK (quantity_change <> 0), balance_after INTEGER NOT NULL CHECK (balance_after >= 0),
  note TEXT NOT NULL DEFAULT '', order_id INTEGER REFERENCES orders(id) ON DELETE SET NULL,
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE email_otps (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL CHECK (purpose IN ('verify_email','admin_login')), code_hash TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0, sent_at DATETIME NOT NULL, expires_at DATETIME NOT NULL, used_at DATETIME);
INSERT INTO sqlite_sequence (name, seq) VALUES ('orders', 2000);