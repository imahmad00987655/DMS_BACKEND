import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { testConnection } from './config/database.js';
import pool, { executeQuery } from './config/database.js';
import { verifyEmailConfig, sendOTPEmail } from './utils/emailService.js';
import authRoutes from './routes/auth.js';
import journalEntryRoutes from './routes/journalEntries.js';
import inventoryItemsRoutes from './routes/inventoryItems.js';
import binCardsRoutes from './routes/binCards.js';
import assetRoutes from './routes/assets.js';
import invoiceRoutes from './routes/invoices.js';
import customerRoutes from './routes/customers.js';
import receiptsRoutes from './routes/receipts.js';
import apSuppliersRoutes from './routes/apSuppliers.js';
import apInvoicesRoutes from './routes/apInvoices.js';
import apPaymentsRoutes from './routes/apPayments.js';
import customerSupplierRoutes from './routes/customerSupplier.js';
import procurementRoutes from './routes/procurement.js';
import partiesRoutes from './routes/parties.js';
import taxRegimesRoutes from './routes/taxRegimes.js';
import taxTypesRoutes from './routes/taxTypes.js';
import taxRatesRoutes from './routes/taxRates.js';
import companiesRoutes from './routes/companies.js';
import companyLocationsRoutes from './routes/companyLocations.js';
import chartOfAccountsRoutes from './routes/chartOfAccounts.js';
import profileRoutes from './routes/profile.js';
import { fileURLToPath } from 'url';
import path from 'path';

// Load environment variables
dotenv.config();

// Log environment variables status on startup (for debugging)
console.log('🔍 Environment Variables Status:');
console.log('  NODE_ENV:', process.env.NODE_ENV || 'not set');
console.log('  JWT_SECRET:', process.env.JWT_SECRET ? `✅ Set (${process.env.JWT_SECRET.length} chars)` : '❌ Not set');
console.log('  DB_HOST:', process.env.DB_HOST || 'not set');
console.log('  PORT:', process.env.PORT || 'not set');

const app = express();
const PORT = process.env.PORT || 5000;

// CRITICAL: Add CORS headers to ALL requests FIRST (before anything else)
app.use((req, res, next) => {
  const origin = req.headers.origin;
  console.log(`🌐 ALL REQUESTS - Method: ${req.method}, Path: ${req.path}, Origin: ${origin || 'No origin'}`);
  
  // Always allow production frontend
  if (origin === 'https://mediumslateblue-snake-987326.hostingersite.com') {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    
    // Handle OPTIONS preflight immediately
    if (req.method === 'OPTIONS') {
      console.log(`✅ OPTIONS preflight handled at top level for ${origin}`);
      return res.sendStatus(204);
    }
  }
  
  next();
});

// Build allowed origins list from env + local defaults
const defaultOrigins = [
  'http://localhost:5173',
  'http://localhost:8080',
  'http://localhost:8081',
  'http://localhost:3000'
];

// Production frontend domain - ALWAYS ADDED (hardcoded for reliability)
const productionFrontend = 'https://mediumslateblue-snake-987326.hostingersite.com';

// Get extra origins from env
const envOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(',').map(origin => origin.trim()).filter(Boolean)
  : [];

// Combine all origins - production domain is always included
const allowedOrigins = [
  ...defaultOrigins,
  ...envOrigins,
  productionFrontend // Always include production domain
].filter(Boolean);

// Remove duplicates
let uniqueOrigins = [...new Set(allowedOrigins)];

// CRITICAL SAFETY CHECK: Ensure production frontend is ALWAYS included
if (uniqueOrigins.indexOf(productionFrontend) === -1) {
  console.warn('⚠️ WARNING: Production frontend not in uniqueOrigins, adding it now!');
  uniqueOrigins.push(productionFrontend);
}

// Log allowed origins on startup
console.log('🌍 CORS Allowed Origins:', uniqueOrigins);
console.log('🌍 CORS_ORIGIN env:', process.env.CORS_ORIGIN || 'Not set');
console.log('🌍 Production Frontend (hardcoded):', productionFrontend);

// CRITICAL: Handle OPTIONS preflight requests FIRST (before CORS middleware)
app.options('*', (req, res) => {
  const origin = req.headers.origin;
  console.log(`🚀 PREFLIGHT OPTIONS - Origin: ${origin || 'No origin'}`);
  console.log(`🚀 PREFLIGHT OPTIONS - Path: ${req.path}`);
  
  // CRITICAL: Always allow production frontend (hardcoded check)
  if (origin === 'https://mediumslateblue-snake-987326.hostingersite.com') {
    console.log(`✅ PREFLIGHT: Production frontend allowed (hardcoded)`);
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Max-Age', '86400');
    return res.sendStatus(204);
  }
  
  // Allow other origins from list
  const isAllowed = !origin || 
                    origin === productionFrontend || 
                    uniqueOrigins.indexOf(origin) !== -1;
  
  if (isAllowed) {
    console.log(`✅ PREFLIGHT: Allowing ${origin || 'no-origin'}`);
    res.header('Access-Control-Allow-Origin', origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Max-Age', '86400');
    return res.sendStatus(204);
  } else {
    console.log(`❌ PREFLIGHT: Blocking ${origin}`);
    return res.status(403).json({ error: 'CORS not allowed' });
  }
});

// CORS configuration - MUST BE BEFORE HELMET to avoid header conflicts
app.use(cors({
  origin: function (origin, callback) {
    console.log(`🔍 CORS Check - Request Origin: ${origin || 'No origin'}`);
    
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) {
      console.log('✅ CORS: No origin, allowing request');
      return callback(null, true);
    }
    
    // CRITICAL: Always allow production frontend domain (hardcoded fallback)
    if (origin === productionFrontend) {
      console.log(`✅ CORS: Production frontend ${origin} allowed (hardcoded)`);
      return callback(null, true);
    }
    
    // Check if origin is in allowed list
    if (uniqueOrigins.indexOf(origin) !== -1) {
      console.log(`✅ CORS: Origin ${origin} is allowed`);
      callback(null, true);
    } else {
      console.log(`❌ CORS: Origin ${origin} is NOT in allowed list`);
      console.log(`📋 Allowed origins: ${uniqueOrigins.join(', ')}`);
      console.log(`📋 Production frontend (hardcoded): ${productionFrontend}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['Content-Type', 'Authorization'],
  preflightContinue: false,
  optionsSuccessStatus: 204,
  maxAge: 86400 // 24 hours
}));

// Final CORS headers fallback - ensures headers are always set for production frontend
app.use((req, res, next) => {
  const origin = req.headers.origin;
  // Always set CORS headers for production frontend
  if (origin === productionFrontend) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
  }
  next();
});

// Security middleware (after CORS)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:", ...uniqueOrigins],
    },
  },
  crossOriginResourcePolicy: { policy: "cross-origin" }, // Allow cross-origin requests for resources
  crossOriginEmbedderPolicy: false, // Disable to allow embedding resources from different origins
}));

// Rate limiting - Increased limits for production
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 1000, // limit each IP to 1000 requests per windowMs (increased from 100)
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limiting for health check and debug endpoints
    return req.path === '/health' || req.path === '/cors-info' || req.path === '/debug-email-env' || req.path === '/test-email';
  }
});

app.use(limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve uploaded files statically with CORS and CORP headers
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use('/uploads', (req, res, next) => {
  // Set CORS headers for static files
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  // Explicitly set Cross-Origin-Resource-Policy to allow cross-origin requests
  res.header('Cross-Origin-Resource-Policy', 'cross-origin');
  // Handle OPTIONS preflight requests
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
}, express.static(path.join(__dirname, 'uploads')));

// Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path} - ${req.ip}`);
  next();
});

// Health check route
app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    version: '2.0.0-cors-fix-v4', // Version to verify latest code is deployed
    productionFrontend: productionFrontend,
    hasTopLevelCORS: true,
    gitCommit: '43939ae', // Latest commit hash
    deployedAt: '2025-12-24T06:40:00Z'
  });
});

// Deployment verification endpoint
app.get('/deployment-info', (req, res) => {
  res.json({
    version: '2.0.0-cors-fix-v4',
    gitCommit: '43939ae',
    features: {
      topLevelCORS: true,
      explicitOPTIONSHandler: true,
      productionFrontendHardcoded: true,
      testUsersEndpoint: true,
      improvedErrorLogging: true
    },
    endpoints: {
      health: '/health',
      corsInfo: '/cors-info',
      testDb: '/test-db',
      testUsers: '/test-users',
      routeInfo: '/route-info'
    },
    timestamp: new Date().toISOString()
  });
});

// Route info endpoint for debugging
app.get('/route-info', (req, res) => {
  res.json({
    success: true,
    message: 'Routes are registered',
    availableRoutes: [
      '/api/auth/login (POST)',
      '/api/auth/register (POST)',
      '/api/auth/verify-otp (POST)',
      '/health (GET)',
      '/cors-info (GET)',
      '/test-db (GET)',
      '/debug-db (GET)'
    ],
    requestPath: req.path,
    requestMethod: req.method,
    baseUrl: req.baseUrl
  });
});

// Test OPTIONS endpoint - VERIFY DEPLOYMENT
app.options('/test-cors', (req, res) => {
  const origin = req.headers.origin;
  console.log(`🧪 TEST CORS OPTIONS - Origin: ${origin}`);
  console.log(`🧪 TEST CORS OPTIONS - This endpoint should work if code is deployed`);
  
  // Always allow production frontend
  if (origin === 'https://mediumslateblue-snake-987326.hostingersite.com') {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');
    return res.sendStatus(204);
  }
  
  res.header('Access-Control-Allow-Origin', origin || '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.sendStatus(204);
});

app.get('/test-cors', (req, res) => {
  res.json({
    success: true,
    message: 'CORS test endpoint - Latest code deployed',
    version: '2.0.0-cors-fix-v3',
    origin: req.headers.origin || 'No origin',
    timestamp: new Date().toISOString(),
    productionFrontend: productionFrontend
  });
});

// CORS debug endpoint - shows allowed origins
app.get('/cors-info', (req, res) => {
  res.json({
    allowedOrigins: uniqueOrigins,
    requestOrigin: req.headers.origin || 'No origin header',
    corsOriginEnv: process.env.CORS_ORIGIN || 'Not set',
    productionFrontend: productionFrontend,
    allEnvVars: {
      CORS_ORIGIN: process.env.CORS_ORIGIN,
      NODE_ENV: process.env.NODE_ENV,
      PORT: process.env.PORT,
      DB_HOST: process.env.DB_HOST,
      // Don't expose sensitive vars
    },
    envOrigins: envOrigins,
    defaultOrigins: defaultOrigins
  });
});

// Debug database connection - shows env vars and tries direct connection
app.get('/debug-db', async (req, res) => {
  const mysql = await import('mysql2/promise');
  
  const config = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'fluent_financial_flow',
    port: parseInt(process.env.DB_PORT) || 3306
  };
  
  // Show config (without password)
  const configSafe = {
    host: config.host,
    user: config.user,
    database: config.database,
    port: config.port,
    passwordSet: !!config.password
  };
  
  let connection = null;
  try {
    console.log('🔍 DEBUG: Attempting connection with:', configSafe);
    
    connection = await mysql.default.createConnection(config);
    await connection.query('SELECT 1 as test');
    
    const [tables] = await connection.execute("SHOW TABLES");
    
    await connection.end();
    
    res.json({
      success: true,
      message: 'Database connection successful',
      config: configSafe,
      tablesCount: tables.length
    });
  } catch (error) {
    if (connection) {
      try {
        await connection.end();
      } catch (e) {}
    }
    
    console.error('🔍 DEBUG: Connection failed:', error);
    
    res.status(500).json({
      success: false,
      message: 'Database connection failed',
      config: configSafe,
      error: {
        message: error.message,
        code: error.code,
        errno: error.errno,
        sqlState: error.sqlState,
        sqlMessage: error.sqlMessage
      }
    });
  }
});

// Test database connection route
app.get('/test-db', async (req, res) => {
  let connection = null;
  try {
    console.log('Testing database connection...');
    const mysql = await import('mysql2/promise');
    const { dbConfig } = await import('./config/database.js');
    
    // Log config (without password)
    console.log('DB Config:', {
      host: dbConfig.host,
      user: dbConfig.user,
      database: dbConfig.database,
      port: dbConfig.port
    });
    
    // Try direct connection first
    try {
      connection = await mysql.default.createConnection(dbConfig);
      await connection.query('SELECT 1');
      console.log('✅ Direct connection successful');
      
      // Test if required tables exist
      const [poAgreements] = await connection.execute("SHOW TABLES LIKE 'po_agreements'");
      const [apSuppliers] = await connection.execute("SHOW TABLES LIKE 'ap_suppliers'");
      const [poAgreementLines] = await connection.execute("SHOW TABLES LIKE 'po_agreement_lines'");
      
      await connection.end();
      
      res.json({
        success: true,
        message: 'Database connection successful',
        tables: {
          po_agreements: poAgreements.length > 0,
          ap_suppliers: apSuppliers.length > 0,
          po_agreement_lines: poAgreementLines.length > 0
        }
      });
    } catch (connError) {
      console.error('❌ Direct connection failed:', connError);
      
      if (connection) {
        try {
          await connection.end();
        } catch (e) {
          // Ignore
        }
      }
      
      // Return detailed error
      res.status(500).json({
        success: false,
        message: 'Database connection failed',
        details: connError.message || 'Unknown error',
        code: connError.code || null,
        errno: connError.errno || null,
        sqlState: connError.sqlState || null,
        config: {
          host: dbConfig.host,
          user: dbConfig.user,
          database: dbConfig.database,
          port: dbConfig.port
        }
      });
    }
  } catch (error) {
    console.error('Database test error:', error);
    
    if (connection) {
      try {
        await connection.end();
      } catch (e) {
        // Ignore
      }
    }
    
    res.status(500).json({
      success: false,
      message: 'Database connection failed',
      error: 'Database test failed',
      details: error.message || 'Unknown error',
      code: error.code || null,
      errno: error.errno || null,
      sqlState: error.sqlState || null,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Performance monitoring endpoint - Check server ping, DB speed, query performance
app.get('/performance', async (req, res) => {
  const startTime = Date.now();
  const metrics = {
    timestamp: new Date().toISOString(),
    server: {
      uptime: process.uptime(),
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB',
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + ' MB',
        rss: Math.round(process.memoryUsage().rss / 1024 / 1024) + ' MB'
      },
      nodeVersion: process.version,
      platform: process.platform
    },
    database: {
      connection: null,
      querySpeed: null,
      poolStats: null
    },
    responseTime: null
  };

  try {
    // Test database connection speed
    const dbStartTime = Date.now();
    const connection = await pool.getConnection();
    const dbConnectionTime = Date.now() - dbStartTime;
    
    metrics.database.connection = {
      status: 'connected',
      latency: dbConnectionTime + ' ms',
      host: process.env.DB_HOST || 'not set',
      database: process.env.DB_NAME || 'not set'
    };

    // Test query speed (simple SELECT 1)
    const queryStartTime = Date.now();
    await connection.query('SELECT 1 as test');
    const queryTime = Date.now() - queryStartTime;
    
    metrics.database.querySpeed = {
      simpleQuery: queryTime + ' ms',
      status: queryTime < 100 ? 'fast' : queryTime < 500 ? 'moderate' : 'slow'
    };

    // Get connection pool stats
    const poolStats = pool.pool;
    metrics.database.poolStats = {
      totalConnections: poolStats._allConnections?.length || 0,
      freeConnections: poolStats._freeConnections?.length || 0,
      connectionLimit: poolStats.config?.connectionLimit || 0,
      queueLength: poolStats._connectionQueue?.length || 0
    };

    connection.release();

    // Test a more complex query (get users count)
    const complexQueryStart = Date.now();
    const [userCount] = await pool.execute('SELECT COUNT(*) as count FROM users');
    const complexQueryTime = Date.now() - complexQueryStart;
    
    metrics.database.querySpeed.complexQuery = complexQueryTime + ' ms';
    metrics.database.querySpeed.userCount = userCount[0]?.count || 0;

    // Overall response time
    metrics.responseTime = (Date.now() - startTime) + ' ms';

    // Performance rating
    const totalTime = Date.now() - startTime;
    if (totalTime < 200) {
      metrics.performance = 'excellent';
    } else if (totalTime < 500) {
      metrics.performance = 'good';
    } else if (totalTime < 1000) {
      metrics.performance = 'moderate';
    } else {
      metrics.performance = 'slow';
    }

    res.json({
      success: true,
      ...metrics
    });

  } catch (error) {
    metrics.database.connection = {
      status: 'failed',
      error: error.message
    };
    metrics.responseTime = (Date.now() - startTime) + ' ms';
    metrics.performance = 'error';

    res.status(500).json({
      success: false,
      ...metrics,
      error: error.message
    });
  }
});

// Debug email environment variables endpoint (as requested by Hostinger support)
app.get('/debug-email-env', (req, res) => {
  const emailVars = {
    EMAIL_HOST: process.env.EMAIL_HOST || null,
    EMAIL_PORT: process.env.EMAIL_PORT || null,
    EMAIL_USER: process.env.EMAIL_USER || null,
    EMAIL_PASS: process.env.EMAIL_PASS ? `Set (length: ${process.env.EMAIL_PASS.length})` : null,
    EMAIL_FROM: process.env.EMAIL_FROM || null,
  };
  
  // Check if all email vars are set
  const allSet = emailVars.EMAIL_HOST && emailVars.EMAIL_USER && emailVars.EMAIL_PASS && emailVars.EMAIL_FROM;
  
  res.json({
    ...emailVars,
    status: allSet ? '✅ All email variables loaded' : '❌ Missing email variables',
    timestamp: new Date().toISOString(),
    note: allSet ? 'Environment variables are working correctly!' : 'Waiting for Hostinger to fix environment variable injection...'
  });
});

// Environment variables status check endpoint (for monitoring when Hostinger fixes the issue)
app.get('/env-status', (req, res) => {
  const requiredVars = {
    // Database
    DB_HOST: process.env.DB_HOST,
    DB_USER: process.env.DB_USER,
    DB_PASSWORD: process.env.DB_PASSWORD ? 'Set' : null,
    DB_NAME: process.env.DB_NAME,
    DB_PORT: process.env.DB_PORT,
    
    // JWT
    JWT_SECRET: process.env.JWT_SECRET ? `Set (${process.env.JWT_SECRET.length} chars)` : null,
    JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || null,
    
    // Email
    EMAIL_HOST: process.env.EMAIL_HOST || null,
    EMAIL_PORT: process.env.EMAIL_PORT || null,
    EMAIL_USER: process.env.EMAIL_USER || null,
    EMAIL_PASS: process.env.EMAIL_PASS ? `Set (${process.env.EMAIL_PASS.length} chars)` : null,
    EMAIL_FROM: process.env.EMAIL_FROM || null,
    
    // Server
    NODE_ENV: process.env.NODE_ENV || null,
    PORT: process.env.PORT || null,
  };
  
  // Count how many are set
  const setCount = Object.values(requiredVars).filter(v => v !== null).length;
  const totalCount = Object.keys(requiredVars).length;
  const percentage = Math.round((setCount / totalCount) * 100);
  
  // Critical vars check
  const criticalVars = ['JWT_SECRET', 'EMAIL_USER', 'EMAIL_PASS', 'EMAIL_FROM'];
  const criticalSet = criticalVars.every(v => requiredVars[v] !== null);
  
  res.json({
    status: criticalSet ? '✅ Critical variables loaded' : '⚠️ Waiting for environment variables',
    percentage: `${percentage}%`,
    setCount,
    totalCount,
    criticalVarsStatus: criticalSet ? '✅ All critical variables set' : '❌ Missing critical variables',
    variables: requiredVars,
    timestamp: new Date().toISOString(),
    message: criticalSet 
      ? '🎉 Environment variables are working! Email service should be functional now.'
      : '⏳ Environment variables not yet loaded. Hostinger support is working on this issue.'
  });
});

// Test email configuration endpoint
app.get('/test-email', async (req, res) => {
  try {
    // Log raw environment variables FIRST (as requested by Hostinger support)
    console.log('═══════════════════════════════════════════════════════════');
    console.log('🔍 RAW ENVIRONMENT VARIABLES CHECK:');
    console.log('EMAIL_HOST from env:', process.env.EMAIL_HOST);
    console.log('EMAIL_PORT from env:', process.env.EMAIL_PORT);
    console.log('EMAIL_USER from env:', process.env.EMAIL_USER);
    console.log('EMAIL_PASS from env:', process.env.EMAIL_PASS ? `Set (length: ${process.env.EMAIL_PASS.length})` : 'NOT SET');
    console.log('EMAIL_FROM from env:', process.env.EMAIL_FROM);
    console.log('All EMAIL_* vars:', {
      EMAIL_HOST: process.env.EMAIL_HOST,
      EMAIL_PORT: process.env.EMAIL_PORT,
      EMAIL_USER: process.env.EMAIL_USER,
      EMAIL_PASS: process.env.EMAIL_PASS ? `Set (length: ${process.env.EMAIL_PASS.length})` : 'NOT SET',
      EMAIL_FROM: process.env.EMAIL_FROM,
    });
    console.log('All process.env keys containing EMAIL:', Object.keys(process.env).filter(key => key.includes('EMAIL')));
    console.log('═══════════════════════════════════════════════════════════');
    
    const email = req.query.email || process.env.EMAIL_USER;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email address required. Use ?email=your@email.com',
        config: {
          EMAIL_HOST: process.env.EMAIL_HOST || 'not set (default: smtp.gmail.com)',
          EMAIL_PORT: process.env.EMAIL_PORT || 'not set (default: 587)',
          EMAIL_USER: process.env.EMAIL_USER ? `${process.env.EMAIL_USER.substring(0, 3)}***` : '❌ NOT SET',
          EMAIL_PASS: process.env.EMAIL_PASS ? '✅ Set' : '❌ NOT SET',
          EMAIL_FROM: process.env.EMAIL_FROM || '❌ NOT SET'
        }
      });
    }

    console.log(`📧 Testing email to: ${email}`);
    
    // First verify configuration
    const configOk = await verifyEmailConfig();
    
    if (!configOk) {
      return res.status(500).json({
        success: false,
        message: 'Email configuration failed',
        config: {
          EMAIL_HOST: process.env.EMAIL_HOST || 'not set',
          EMAIL_PORT: process.env.EMAIL_PORT || 'not set',
          EMAIL_USER: process.env.EMAIL_USER ? '✅ Set' : '❌ NOT SET',
          EMAIL_PASS: process.env.EMAIL_PASS ? '✅ Set' : '❌ NOT SET',
          EMAIL_FROM: process.env.EMAIL_FROM || '❌ NOT SET'
        },
        hint: 'Check environment variables in Hostinger dashboard'
      });
    }

    // Try to send a test email
    const testOTP = '123456';
    await sendOTPEmail(email, testOTP, 'email_verification');
    
    res.json({
      success: true,
      message: `Test email sent successfully to ${email}`,
      config: {
        EMAIL_HOST: process.env.EMAIL_HOST || 'not set',
        EMAIL_PORT: process.env.EMAIL_PORT || 'not set',
        EMAIL_USER: process.env.EMAIL_USER ? `${process.env.EMAIL_USER.substring(0, 3)}***` : '❌ NOT SET',
        EMAIL_PASS: process.env.EMAIL_PASS ? '✅ Set' : '❌ NOT SET',
        EMAIL_FROM: process.env.EMAIL_FROM || '❌ NOT SET'
      },
      note: 'Check your email inbox (and spam folder) for the test OTP: 123456'
    });
  } catch (error) {
    console.error('❌ Test email error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send test email',
      error: error.message,
      errorCode: error.code,
      config: {
        EMAIL_HOST: process.env.EMAIL_HOST || 'not set',
        EMAIL_PORT: process.env.EMAIL_PORT || 'not set',
        EMAIL_USER: process.env.EMAIL_USER ? '✅ Set' : '❌ NOT SET',
        EMAIL_PASS: process.env.EMAIL_PASS ? '✅ Set' : '❌ NOT SET',
        EMAIL_FROM: process.env.EMAIL_FROM || '❌ NOT SET'
      },
      hint: error.message?.includes('Invalid login') 
        ? 'Check EMAIL_USER and EMAIL_PASS credentials'
        : error.message?.includes('ECONNREFUSED')
        ? 'Check EMAIL_HOST and EMAIL_PORT - SMTP server might be blocked'
        : 'Check backend logs for more details'
    });
  }
});

// Test JWT_SECRET endpoint
app.get('/test-jwt', (req, res) => {
  // Reload environment variables
  dotenv.config();
  
  // Use same logic as generateToken - hardcoded fallback
  const jwtSecret = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';
  const usingFallback = !process.env.JWT_SECRET;
  
  res.json({
    success: true, // Always true - using hardcoded fallback
    message: usingFallback 
      ? 'JWT_SECRET using hardcoded fallback (login will work)' 
      : 'JWT_SECRET is configured from environment',
    jwtSecretSet: !!process.env.JWT_SECRET,
    usingFallback: usingFallback,
    jwtSecretLength: jwtSecret.length,
    hint: usingFallback 
      ? 'Using hardcoded JWT_SECRET - login will work. Contact Hostinger support to fix environment variables.'
      : `JWT_SECRET loaded from environment (${jwtSecret.length} chars)`,
    nodeEnv: process.env.NODE_ENV
  });
});

// Test users table endpoint - check if users table exists and has required columns
app.get('/test-users', async (req, res) => {
  try {
    console.log('Testing users table and required columns...');
    const mysql = await import('mysql2/promise');
    const { dbConfig } = await import('./config/database.js');
    
    const connection = await mysql.default.createConnection(dbConfig);
    
    // Check if users table exists
    const [tables] = await connection.execute(
      "SHOW TABLES LIKE 'users'"
    );
    
    if (tables.length === 0) {
      await connection.end();
      return res.status(500).json({
        success: false,
        error: 'Users table does not exist',
        message: 'Please import the database schema'
      });
    }
    
    // Get all columns from users table
    const [columns] = await connection.execute(
      "SHOW COLUMNS FROM users"
    );
    
    const columnNames = columns.map(col => col.Field);
    
    // Required columns for login
    const requiredColumns = ['id', 'email', 'password_hash', 'role', 'is_active', 'is_verified', 'first_name', 'last_name'];
    const missingColumns = requiredColumns.filter(col => !columnNames.includes(col));
    
    // Check if user_sessions table exists
    const [sessionsTable] = await connection.execute(
      "SHOW TABLES LIKE 'user_sessions'"
    );
    
    // Try to query users table
    const [users] = await connection.execute('SELECT COUNT(*) as count FROM users');
    
    await connection.end();
    
    res.json({
      success: missingColumns.length === 0 && sessionsTable.length > 0,
      message: missingColumns.length === 0 && sessionsTable.length > 0 
        ? 'Users table is ready for login' 
        : 'Users table has missing columns or user_sessions table missing',
      usersCount: users[0].count,
      tableExists: true,
      columns: columnNames,
      requiredColumns: requiredColumns,
      missingColumns: missingColumns,
      userSessionsTableExists: sessionsTable.length > 0
    });
  } catch (error) {
    console.error('Error testing users table:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to test users table',
      details: error.message,
      code: error.code,
      errno: error.errno
    });
  }
});

// Test suppliers endpoint
app.get('/test-suppliers', async (req, res) => {
  try {
    console.log('Testing suppliers...');
    const mysql = await import('mysql2/promise');
    const { dbConfig } = await import('./config/database.js');
    
    const connection = await mysql.default.createConnection(dbConfig);
    
    const [suppliers] = await connection.execute('SELECT supplier_id, supplier_name FROM ap_suppliers LIMIT 10');
    
    await connection.end();
    
    res.json({
      success: true,
      suppliers: suppliers
    });
  } catch (error) {
    console.error('Error fetching suppliers:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch suppliers',
      details: error.message
    });
  }
});

// Procurement suppliers endpoint (no auth) - Fetch existing suppliers with party info
app.get('/procurement-suppliers', async (req, res) => {
  try {
    console.log('Fetching existing suppliers with party information...');
    const mysql = await import('mysql2/promise');
    const { dbConfig } = await import('./config/database.js');
    
    const connection = await mysql.default.createConnection(dbConfig);
    
    // Fetch existing suppliers (ZIC, Steel Company, Akhter) with their party information
    const [suppliers] = await connection.execute(`
      SELECT 
        sp.supplier_id,
        sp.supplier_name,
        sp.supplier_number,
        sp.supplier_type,
        sp.supplier_class,
        sp.supplier_category,
        sp.party_id,
        p.party_name,
        sp.status as supplier_status,
        'ACTIVE' as status,
        (
          SELECT COUNT(*) 
          FROM party_sites ps 
          WHERE ps.party_id = sp.party_id AND ps.status = 'ACTIVE'
        ) as sites_count
      FROM ap_suppliers sp
      JOIN parties p ON sp.party_id = p.party_id
      WHERE sp.status = 'ACTIVE'
      ORDER BY sp.supplier_name
    `);
    
    console.log('Raw suppliers data from database:', suppliers);
    
    // Ensure we're returning the correct supplier names
    const processedSuppliers = suppliers.map(supplier => ({
      ...supplier,
      supplier_name: supplier.supplier_name, // This should be the actual supplier name
      display_name: `${supplier.supplier_name} (${supplier.supplier_number})` // Enhanced display name
    }));
    
    console.log('Processed suppliers data:', processedSuppliers);
    
    await connection.end();
    
    res.json(processedSuppliers);
  } catch (error) {
    console.error('Error fetching suppliers:', error);
    res.status(500).json({ error: 'Failed to fetch suppliers' });
  }
});

// Test purchase agreement creation route
app.post('/test-agreement', async (req, res) => {
  try {
    console.log('=== TEST AGREEMENT CREATION ===');
    console.log('Request body:', JSON.stringify(req.body, null, 2));
    
    const {
      supplier_id,
      site_id,
      description = '',
      lines = [],
      agreement_type = '',
      status = '',
      approval_status = '',
      currency_code = '',
      exchange_rate = '',
      total_amount = '',
      agreement_date = '',
      effective_start_date = '',
      effective_end_date = ''
    } = req.body;
    
    if (!supplier_id) {
      return res.status(400).json({ error: 'supplier_id is required' });
    }
    
    const mysql = await import('mysql2/promise');
    const { dbConfig } = await import('./config/database.js');
    
    console.log('Creating database connection...');
    const connection = await mysql.default.createConnection(dbConfig);
    console.log('Database connection created successfully');
    
    // Check if supplier exists in ap_suppliers
    let supplierExists = false;
    try {
      const [existingSuppliers] = await connection.execute('SELECT supplier_id FROM ap_suppliers WHERE supplier_id = ?', [supplier_id]);
      supplierExists = existingSuppliers.length > 0;
    } catch (error) {
      console.log('Error checking supplier:', error.message);
    }
    
    if (!supplierExists) {
      console.log(`Supplier ${supplier_id} does not exist in ap_suppliers, cannot create agreement`);
      await connection.end();
      return res.status(400).json({ 
        error: 'Supplier not found',
        details: `Supplier ID ${supplier_id} does not exist in the supplier profiles` 
      });
    }
    console.log('Database connection created successfully');
    
    // Generate agreement ID and number
    const agreementId = Date.now();
    const finalAgreementNumber = `PA${agreementId}`;
    const today = new Date().toISOString().split('T')[0];
    const endDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    
    // Calculate total amount from line items if not provided
    let calculatedTotalAmount = 0;
    if (total_amount && !isNaN(parseFloat(total_amount))) {
      calculatedTotalAmount = parseFloat(total_amount);
    } else if (lines && lines.length > 0) {
      calculatedTotalAmount = lines.reduce((total, line) => {
        return total + (Number(line.line_amount) || 0);
      }, 0);
    }

    console.log('Creating agreement with:', {
      agreementId,
      finalAgreementNumber,
      supplier_id,
      description,
      calculatedTotalAmount
    });
    
    console.log('About to insert agreement header...');
    // Insert agreement header with minimal required fields
    const result = await connection.execute(`
      INSERT INTO po_agreements (
        agreement_id, 
        agreement_number, 
        agreement_type, 
        supplier_id, 
        supplier_site_id,
        buyer_id, 
        agreement_date, 
        effective_start_date, 
        effective_end_date,
        currency_code, 
        exchange_rate, 
        total_amount, 
        amount_used,
        payment_terms_id,
        description, 
        notes, 
        created_by,
        status,
        approval_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      agreementId,           // agreement_id
      finalAgreementNumber,  // agreement_number
      agreement_type,        // agreement_type
      supplier_id,          // supplier_id
      site_id || 1,         // supplier_site_id (use provided site_id or default to 1)
      1,                    // buyer_id (default)
      agreement_date || today,                // agreement_date
      effective_start_date || today,                // effective_start_date
      effective_end_date || endDate,              // effective_end_date
      currency_code || 'USD',                // currency_code
      exchange_rate || 1.0,                  // exchange_rate
      calculatedTotalAmount,                 // total_amount
      0,                    // amount_used (start with 0)
      30,                   // payment_terms_id (default)
      description,          // description
      '',                   // notes
      1,                    // created_by (default)
      status,               // status
      approval_status       // approval_status
    ]);
    
    console.log('Agreement header inserted successfully');
    
    // Create line items if provided
    if (lines && lines.length > 0) {
      console.log('Creating line items:', lines.length);
      
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        console.log(`Processing line ${i + 1}:`, line);
        
        // Use simple timestamp-based line ID
        const lineId = Date.now() + i;
        
        await connection.execute(`
          INSERT INTO po_agreement_lines (
            line_id, agreement_id, line_number, item_code, item_name, description,
            category, uom, quantity, unit_price, line_amount, min_quantity,
            max_quantity, need_by_date, suggested_supplier, suggested_supplier_id, notes
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
          lineId, 
          agreementId, 
          i + 1, 
          line.item_code || '', 
          line.item_name || '',
          line.description || '', 
          line.category || '', 
          line.uom || 'EACH',
          Number(line.quantity) || 1, 
          Number(line.unit_price) || 0, 
          Number(line.line_amount) || 0,
          line.min_quantity ? Number(line.min_quantity) : null, 
          line.max_quantity ? Number(line.max_quantity) : null,
          line.need_by_date || null, 
          line.suggested_supplier || '',
          line.suggested_supplier_id ? Number(line.suggested_supplier_id) : null, 
          line.notes || ''
        ]);
      }
      
      console.log('Line items created successfully');
    }
    
    await connection.end();
    
    console.log('Agreement created successfully');
    
    res.status(201).json({
      success: true,
      message: 'Agreement created successfully',
      agreement: {
        agreement_id: agreementId,
        agreement_number: finalAgreementNumber,
        supplier_id,
        description,
        lines_count: lines.length
      }
    });
    
  } catch (error) {
    console.error('Error creating purchase agreement:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({
      success: false,
      error: 'Failed to create agreement',
      details: error.message,
      stack: error.stack
    });
  }
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/profile', profileRoutes);
app.use('/api/journal-entries', journalEntryRoutes);
app.use('/api/inventory-items', inventoryItemsRoutes);
app.use('/api/bin-cards', binCardsRoutes);
app.use('/api/assets', assetRoutes);
app.use('/api/invoices', invoiceRoutes);
app.use('/api/customers', customerRoutes);
app.use('/api/receipts', receiptsRoutes);


// Normalized Payables System Routes (Oracle E-Business Suite R12 Model)
app.use('/api/ap/suppliers', apSuppliersRoutes);
app.use('/api/ap/invoices', apInvoicesRoutes);
app.use('/api/ap/payments', apPaymentsRoutes);

// Customer/Supplier Management System Routes (Oracle Apps R12 Structure)
app.use('/api/customer-supplier', customerSupplierRoutes);

// Procurement System Routes
app.use('/api/procurement', procurementRoutes);
app.use('/api/parties', partiesRoutes);

// Tax Configuration Routes
app.use('/api/tax/regimes', taxRegimesRoutes);
app.use('/api/tax/types', taxTypesRoutes);
app.use('/api/tax/rates', taxRatesRoutes);

// Company Setup Routes
app.use('/api/companies', companiesRoutes);
app.use('/api/company-locations', companyLocationsRoutes);

// Chart of Accounts Routes
app.use('/api/chart-of-accounts', chartOfAccountsRoutes);


// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Error:', error);
  
  // Handle specific error types
  if (error.name === 'ValidationError') {
    return res.status(400).json({
      success: false,
      message: 'Validation error',
      errors: error.errors
    });
  }
  
  if (error.name === 'UnauthorizedError') {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized'
    });
  }
  
  // Default error response
  res.status(500).json({
    success: false,
    message: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : error.message
  });
});

// Start server
const startServer = async () => {
  try {
    // Test database connection (don't crash server if it fails – just log)
    const dbStatus = await testConnection();
    if (!dbStatus.ok) {
      console.error('❌ Failed to connect to database on startup. Server will still start, but DB-dependent routes may fail.');
    }

    // Test email configuration (also don't block server start)
    const emailConfigured = await verifyEmailConfig();
    if (!emailConfigured) {
      console.warn('⚠️ Email service not configured. OTP functionality will not work.');
    }

    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📧 Email service: ${emailConfigured ? '✅ Configured' : '❌ Not configured'}`);
      console.log(`🗄️ Database: ${dbStatus.ok ? '✅ Connected' : '❌ Connection failed'}`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    // Do not force-exit; let platform handle restart / logs
  }
};

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  process.exit(0);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

startServer(); 