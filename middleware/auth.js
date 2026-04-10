import { verifyToken } from '../utils/authUtils.js';
import { executeQuery } from '../config/database.js';

// Middleware to verify JWT token
export const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({ 
        success: false, 
        message: 'Access token required' 
      });
    }

    const decoded = verifyToken(token);
    
    // Check if user still exists and is active
    const users = await executeQuery(
      'SELECT id, email, role, is_active FROM users WHERE id = ? AND is_active = TRUE',
      [decoded.userId]
    );

    if (users.length === 0) {
      return res.status(401).json({ 
        success: false, 
        message: 'User not found or inactive' 
      });
    }

    req.user = {
      id: users[0].id,
      userId: users[0].id, // Add this for compatibility
      email: users[0].email,
      role: users[0].role
    };

    next();
  } catch (error) {
    // Log specific error for debugging
    console.error('🔴 Authentication failed:', {
      errorName: error.name,
      errorMessage: error.message,
      tokenPresent: !!token,
      tokenLength: token ? token.length : 0
    });
    
    // Provide more specific error messages
    let errorMessage = 'Invalid or expired token';
    if (error.name === 'TokenExpiredError') {
      errorMessage = 'Token has expired. Please login again.';
    } else if (error.name === 'JsonWebTokenError') {
      errorMessage = 'Invalid token. Please login again.';
    }
    
    return res.status(403).json({ 
      success: false, 
      message: errorMessage 
    });
  }
};

// Middleware to check if user has required role
export const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        success: false, 
        message: 'Authentication required' 
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ 
        success: false, 
        message: 'Insufficient permissions' 
      });
    }

    next();
  };
};

// Middleware to check if user is verified
export const requireVerification = async (req, res, next) => {
  try {
    const users = await executeQuery(
      'SELECT is_verified FROM users WHERE id = ?',
      [req.user.id]
    );

    if (users.length === 0 || !users[0].is_verified) {
      return res.status(403).json({ 
        success: false, 
        message: 'Email verification required' 
      });
    }

    next();
  } catch (error) {
    return res.status(500).json({ 
      success: false, 
      message: 'Server error' 
    });
  }
};

// Optional authentication middleware (doesn't fail if no token)
export const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
      const decoded = verifyToken(token);
      
      const users = await executeQuery(
        'SELECT id, email, role, is_active FROM users WHERE id = ? AND is_active = TRUE',
        [decoded.userId]
      );

      if (users.length > 0) {
        req.user = {
          id: users[0].id,
          email: users[0].email,
          role: users[0].role
        };
      }
    }

    next();
  } catch (error) {
    // Continue without authentication
    next();
  }
};

// Rate limiting middleware
export const rateLimit = (windowMs, maxRequests) => {
  const requests = new Map();

  return (req, res, next) => {
    const key = req.ip;
    const now = Date.now();
    const windowStart = now - windowMs;

    // Clean old entries
    if (requests.has(key)) {
      const userRequests = requests.get(key).filter(time => time > windowStart);
      requests.set(key, userRequests);
    } else {
      requests.set(key, []);
    }

    const userRequests = requests.get(key);

    if (userRequests.length >= maxRequests) {
      // Calculate when the oldest request in window will expire
      const oldestRequest = Math.min(...userRequests);
      const retryAfter = Math.ceil((oldestRequest + windowMs - now) / 1000); // seconds until retry
      return res.status(429).json({ 
        success: false, 
        message: 'Too many requests, please try again later',
        retryAfter: retryAfter > 0 ? retryAfter : 0, // seconds until can retry
        limit: maxRequests,
        windowMinutes: Math.ceil(windowMs / 60000)
      });
    }

    userRequests.push(now);
    next();
  };
}; 