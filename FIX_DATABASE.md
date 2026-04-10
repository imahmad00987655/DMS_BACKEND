# Fix Database - Add Missing Columns

## Problem
Login is failing with 500 error because users table is missing required columns.

## Solution
Run these SQL commands in phpMyAdmin:

### Step 1: Add Missing Columns to users table

```sql
-- Add role column (if it doesn't exist)
ALTER TABLE users 
ADD COLUMN role VARCHAR(50) DEFAULT 'user' AFTER email;

-- Add is_active column (if it doesn't exist)
ALTER TABLE users 
ADD COLUMN is_active BOOLEAN DEFAULT TRUE AFTER role;

-- Add is_verified column (if it doesn't exist)
ALTER TABLE users 
ADD COLUMN is_verified BOOLEAN DEFAULT FALSE AFTER is_active;
```

**Note:** If you get "Duplicate column name" error, that column already exists - skip it.

### Step 2: Update Existing Users

```sql
-- Set default values for existing users
UPDATE users SET role = 'user' WHERE role IS NULL;
UPDATE users SET is_active = TRUE WHERE is_active IS NULL;
UPDATE users SET is_verified = TRUE WHERE is_verified IS NULL;

-- Set admin user (change email if needed)
UPDATE users SET role = 'admin' WHERE email = 'admin@accuflow.com';
```

### Step 3: Create user_sessions table

```sql
CREATE TABLE IF NOT EXISTS user_sessions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  token_hash VARCHAR(255) NOT NULL,
  device_info TEXT,
  ip_address VARCHAR(45),
  expires_at DATETIME NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_id (user_id),
  INDEX idx_token_hash (token_hash),
  INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

## After Running SQL

1. Redeploy backend on Hostinger
2. Try login again
3. Should work now!

## Verify

Check if columns exist:
```sql
SHOW COLUMNS FROM users;
```

You should see: `role`, `is_active`, `is_verified`

