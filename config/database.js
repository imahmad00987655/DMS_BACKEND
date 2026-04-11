import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

/** Hostinger / panel UIs sometimes save literal "..." as part of the value — strip one pair. */
function mysqlPasswordFromEnv() {
  const raw = process.env.DB_PASSWORD;
  if (raw == null || raw === '') return '';
  let p = String(raw).trim();
  if (
    (p.startsWith('"') && p.endsWith('"')) ||
    (p.startsWith("'") && p.endsWith("'"))
  ) {
    p = p.slice(1, -1);
  }
  return p;
}

export const dbConfig = {
  // Use 127.0.0.1 not "localhost": Node resolves localhost → ::1 (IPv6); MySQL often grants 127.0.0.1 / localhost, not ::1 → Access denied.
  host: process.env.DB_HOST || '127.0.0.1',
  user: process.env.DB_USER || '',
  password: mysqlPasswordFromEnv(),
  database: process.env.DB_NAME || '',
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT) || 20, // Increased from 10 to 20
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0,
  acquireTimeout: 60000, // 60 seconds
  timeout: 60000 // 60 seconds
};


// Create connection pool
const pool = mysql.createPool(dbConfig);

// Test database connection with detailed logging (no secrets)
export const testConnection = async () => {
  try {
    const connection = await pool.getConnection();
    // Simple ping
    await connection.query('SELECT 1');
    connection.release();

    console.log('✅ Database connected successfully', {
      host: dbConfig.host,
      user: dbConfig.user,
      database: dbConfig.database,
      port: dbConfig.port
    });

    return { ok: true };
  } catch (error) {
    console.error('❌ Database connection failed', {
      message: error.message,
      code: error.code,
      errno: error.errno,
      sqlState: error.sqlState,
      config: {
        host: dbConfig.host,
        user: dbConfig.user,
        database: dbConfig.database,
        port: dbConfig.port
      }
    });

    return { ok: false, error };
  }
};

// Execute query with error handling and performance tracking
export const executeQuery = async (query, params = []) => {
  const startTime = Date.now();
  try {
    const [rows] = await pool.execute(query, params);
    const executionTime = Date.now() - startTime;
    
    // Log slow queries (> 500ms) for optimization
    if (executionTime > 500) {
      console.warn(`⚠️ Slow query detected (${executionTime}ms):`, query.substring(0, 100));
    }
    
    return rows;
  } catch (error) {
    const executionTime = Date.now() - startTime;
    console.error(`❌ Database query error (${executionTime}ms):`, error);
    throw new Error(`Database error: ${error.message}`);
  }
};

// Execute transaction
export const executeTransaction = async (queries) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    
    const results = [];
    for (const { query, params = [] } of queries) {
      const [rows] = await connection.execute(query, params);
      results.push(rows);
    }
    
    await connection.commit();
    return results;
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
};

// Export pool as default
export default pool;

