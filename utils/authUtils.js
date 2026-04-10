import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

// Generate JWT token
export const generateToken = (userId, email, role) => {
  // Use environment variable if available, otherwise use hardcoded fallback
  // This ensures login works both when env var is loaded and when it's not
  const jwtSecret = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';
  
  // Log status (only once on startup, not on every token generation)
  if (process.env.JWT_SECRET) {
    // Only log once - check if we've logged before
    if (!global.jwtSecretLogged) {
      console.log('✅ JWT_SECRET loaded from environment variables');
      global.jwtSecretLogged = true;
    }
  } else {
    if (!global.jwtFallbackLogged) {
      console.log('⚠️ JWT_SECRET not found in env - using fallback (login will work)');
      console.log('⚠️ When Hostinger env vars load, it will automatically use them');
      global.jwtFallbackLogged = true;
    }
  }
  
  return jwt.sign(
    { 
      userId, 
      email, 
      role,
      iat: Math.floor(Date.now() / 1000)
    },
    jwtSecret,
    { 
      // Increased expiration to 90 days (3 months) for better user experience
      // Can be overridden by JWT_EXPIRES_IN environment variable
      expiresIn: process.env.JWT_EXPIRES_IN || '90d' 
    }
  );
};

// Verify JWT token
export const verifyToken = (token) => {
  // Use environment variable if available, otherwise use hardcoded fallback
  // Note: For production, JWT_SECRET should be set in environment variables
  const jwtSecret = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';
  
  try {
    return jwt.verify(token, jwtSecret);
  } catch (error) {
    // Log the specific error for debugging
    console.error('🔴 Token verification failed:', error.name, error.message);
    throw error; // Re-throw to let middleware handle it
  }
};

// Hash password
export const hashPassword = async (password) => {
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
};

// Compare password
export const comparePassword = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};

// Generate OTP
export const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Generate reset token
export const generateResetToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Hash token for storage
export const hashToken = (token) => {
  return crypto.createHash('sha256').update(token).digest('hex');
};

// Generate device fingerprint
export const generateDeviceFingerprint = (userAgent, ipAddress) => {
  const fingerprint = crypto
    .createHash('md5')
    .update(`${userAgent}${ipAddress}`)
    .digest('hex');
  return fingerprint;
};

// Validate email format
export const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

// Validate password strength - FIXED VERSION
export const validatePassword = (password) => {
  const errors = [];
  
  if (password.length < 6) {
    errors.push('Password must be at least 6 characters long');
  }
  
  if (password.length > 50) {
    errors.push('Password must be less than 50 characters');
  }
  
  // Check for at least one letter and one number
  const hasLetter = /[a-zA-Z]/.test(password);
  const hasNumber = /\d/.test(password);
  
  if (!hasLetter) {
    errors.push('Password must contain at least one letter');
  }
  
  if (!hasNumber) {
    errors.push('Password must contain at least one number');
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

// Sanitize input
export const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  return input.trim().replace(/[<>]/g, '');
};

// Rate limiting helper
export const createRateLimitKey = (identifier, action) => {
  return `${identifier}:${action}`;
};

// Create audit log - FIXED VERSION
export const createAuditLog = async (executeQuery, userId, action, details, ipAddress, userAgent) => {
  try {
    await executeQuery(
      'INSERT INTO audit_logs (user_id, action, details, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)',
      [userId, action, details, ipAddress, userAgent]
    );
  } catch (error) {
    console.error('Failed to create audit log:', error.message);
  }
}; 