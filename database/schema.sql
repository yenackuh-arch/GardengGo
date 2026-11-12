-- =====================================================================
-- GardenGo database schema  (MySQL 8.0.16 or newer / MariaDB 10.2 or newer)
-- Project: GardenGo, a web-based plant ordering system for Gripalda's Garden, Bay, Laguna.
--
-- HOW TO RUN (MySQL Workbench):
--   1. Open your connection, then File > Open SQL Script... and choose this file.
--   2. Click the lightning bolt (Execute). Run it ONCE.
-- This script only creates things. It never drops tables or deletes data.
-- It is safe to run again: every CREATE uses IF NOT EXISTS.
-- =====================================================================

CREATE DATABASE IF NOT EXISTS gardengo
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE gardengo;

-- ---------------------------------------------------------------------
-- 1. users: customers AND the garden owner/staff (role decides what they can open)
--    Passwords are never stored. Only a hash made by Flask (password_hash).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  full_name     VARCHAR(80)  NOT NULL,
  email         VARCHAR(120) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role          ENUM('customer','admin') NOT NULL DEFAULT 'customer',
  phone         VARCHAR(20)  NULL,
  address       VARCHAR(120) NULL,
  city          VARCHAR(60)  NULL,
  province      VARCHAR(60)  NULL,
  is_active     TINYINT(1)   NOT NULL DEFAULT 1,      -- 0 = deactivated account
  email_verified TINYINT(1)  NOT NULL DEFAULT 0,      -- 1 = the customer confirmed their email with a 6-digit code
  created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_email (email),                  -- one account per email
  KEY idx_users_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 2. categories: Indoor, Outdoor, Succulent, Flowering, ...
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS categories (
  id   INT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(40)  NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_categories_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 3. plants: the catalog. stock_quantity is UNSIGNED, so MySQL itself refuses negative stock.
--    is_available = 0 hides the plant from customers (used instead of deleting a plant that has orders).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS plants (
  id             INT UNSIGNED  NOT NULL AUTO_INCREMENT,
  category_id    INT UNSIGNED  NOT NULL,
  name           VARCHAR(60)   NOT NULL,
  description    VARCHAR(300)  NOT NULL DEFAULT '',
  price          DECIMAL(10,2) NOT NULL,               -- Philippine pesos
  stock_quantity INT UNSIGNED  NOT NULL DEFAULT 0,
  image_path     VARCHAR(255)  NULL,                   -- file name inside static/uploads/plants/ (or a full web link)
  is_available   TINYINT(1)    NOT NULL DEFAULT 1,
  created_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_plants_name (name),
  KEY idx_plants_category (category_id),
  KEY idx_plants_available (is_available),
  CONSTRAINT fk_plants_category FOREIGN KEY (category_id) REFERENCES categories (id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT chk_plants_price CHECK (price > 0 AND price <= 100000),
  CONSTRAINT chk_plants_stock CHECK (stock_quantity <= 9999)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 4. orders: one row per order. The customer-facing order ID is 'GG-' + id (first one is GG-2001).
--    Contact and address are copied here, so later profile edits never change old orders.
--    stock_deducted makes sure stock is taken off once and given back once (no double changes).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS orders (
  id             INT UNSIGNED  NOT NULL AUTO_INCREMENT,
  user_id        INT UNSIGNED  NOT NULL,
  status         ENUM('Pending','Confirmed','Processing','Ready for Pickup','Completed','Cancelled')
                 NOT NULL DEFAULT 'Pending',
  fulfillment    ENUM('pickup','delivery') NOT NULL,
  delivery_fee   DECIMAL(10,2) NOT NULL DEFAULT 0.00,
  total_amount   DECIMAL(10,2) NOT NULL,               -- items + delivery fee, saved at the time of ordering
  contact_name   VARCHAR(80)   NOT NULL,
  contact_phone  VARCHAR(20)   NOT NULL,
  address        VARCHAR(120)  NOT NULL,
  city           VARCHAR(60)   NOT NULL,
  province       VARCHAR(60)   NOT NULL,
  notes          VARCHAR(200)  NULL,
  stock_deducted TINYINT(1)    NOT NULL DEFAULT 1,
  created_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_orders_user (user_id, created_at),           -- "My Orders" and a customer's order history
  KEY idx_orders_status (status),                      -- admin filter by status, pending count
  KEY idx_orders_created (created_at),                 -- admin filter by date, sales chart
  CONSTRAINT fk_orders_user FOREIGN KEY (user_id) REFERENCES users (id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT chk_orders_fee CHECK (delivery_fee >= 0),
  CONSTRAINT chk_orders_total CHECK (total_amount >= 0)
) ENGINE=InnoDB AUTO_INCREMENT=2001 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 5. order_items: the plants inside each order (an order can have many).
--    unit_price and plant_name are COPIED at purchase time, so editing a plant later
--    never changes the history or the totals of old orders.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS order_items (
  id         INT UNSIGNED  NOT NULL AUTO_INCREMENT,
  order_id   INT UNSIGNED  NOT NULL,
  plant_id   INT UNSIGNED  NOT NULL,
  plant_name VARCHAR(60)   NOT NULL,
  unit_price DECIMAL(10,2) NOT NULL,
  quantity   INT UNSIGNED  NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_order_plant (order_id, plant_id),      -- the same plant appears once per order
  KEY idx_items_plant (plant_id),                      -- popular plants report
  CONSTRAINT fk_items_order FOREIGN KEY (order_id) REFERENCES orders (id)
    ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT fk_items_plant FOREIGN KEY (plant_id) REFERENCES plants (id)
    ON UPDATE CASCADE ON DELETE RESTRICT,              -- a plant that was ordered can never be deleted
  CONSTRAINT chk_items_qty CHECK (quantity >= 1),
  CONSTRAINT chk_items_price CHECK (unit_price > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 6. stock_movements: a history of every stock change (the Inventory page's history table).
--    quantity_change is + or -, balance_after is the stock right after the change.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS stock_movements (
  id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
  plant_id        INT UNSIGNED NOT NULL,
  movement_type   ENUM('initial_stock','order_placed','order_cancelled','restock','damaged_lost','correction') NOT NULL,
  quantity_change INT          NOT NULL,
  balance_after   INT UNSIGNED NOT NULL,
  note            VARCHAR(120) NOT NULL DEFAULT '',
  order_id        INT UNSIGNED NULL,                   -- set when the change came from an order
  created_by      INT UNSIGNED NULL,                   -- the admin who made a manual change
  created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_movements_plant (plant_id, created_at),
  KEY idx_movements_order (order_id),
  CONSTRAINT fk_movements_plant FOREIGN KEY (plant_id) REFERENCES plants (id)
    ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT fk_movements_order FOREIGN KEY (order_id) REFERENCES orders (id)
    ON UPDATE CASCADE ON DELETE SET NULL,
  CONSTRAINT fk_movements_user FOREIGN KEY (created_by) REFERENCES users (id)
    ON UPDATE CASCADE ON DELETE SET NULL,
  CONSTRAINT chk_movements_change CHECK (quantity_change <> 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS email_otps (
  id         INT UNSIGNED     NOT NULL AUTO_INCREMENT,
  user_id    INT UNSIGNED     NOT NULL,
  purpose    ENUM('verify_email','admin_login') NOT NULL,
  code_hash  CHAR(64)         NOT NULL,
  attempts   TINYINT UNSIGNED NOT NULL DEFAULT 0,
  sent_at    DATETIME         NOT NULL,
  expires_at DATETIME         NOT NULL,
  used_at    DATETIME         NULL,
  PRIMARY KEY (id),
  KEY idx_otps_lookup (user_id, purpose, id),
  CONSTRAINT fk_otps_user FOREIGN KEY (user_id) REFERENCES users (id)
    ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
