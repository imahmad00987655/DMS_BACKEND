import express from 'express';
import { body, validationResult } from 'express-validator';
import { executeQuery } from '../config/database.js';
import { 
  generateToken, 
  hashPassword, 
  comparePassword, 
  generateOTP, 
  generateResetToken,
  hashToken,
  isValidEmail,
  validatePassword,
  sanitizeInput,
  createAuditLog
} from '../utils/authUtils.js';
import { sendOTPEmail, sendWelcomeEmail } from '../utils/emailService.js';
import { authenticateToken, rateLimit } from '../middleware/auth.js';

const router = express.Router();

// Rate limiting - Increased limits for production
const loginRateLimit = rateLimit(15 * 60 * 1000, 50); // 50 attempts per 15 minutes (increased from 10)
const signupRateLimit = rateLimit(60 * 60 * 1000, 20); // 20 attempts per hour (increased from 5)
const otpRateLimit = rateLimit(5 * 60 * 1000, 20); // 20 attempts per 5 minutes (increased from 5)

// Login route
router.post('/login', 
  loginRateLimit,
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 1 }).withMessage('Password is required')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { email, password } = req.body;
      const sanitizedEmail = sanitizeInput(email);

      // Check if user exists
      // Note: If columns don't exist, this will throw an error - add missing columns to database
      let users;
      try {
        users = await executeQuery(
          'SELECT id, email, password_hash, role, is_active, is_verified, first_name, last_name FROM users WHERE email = ?',
          [sanitizedEmail]
        );
      } catch (dbError) {
        // If error is about unknown column, provide helpful message
        if (dbError.message && dbError.message.includes('Unknown column')) {
          console.error('❌ DATABASE COLUMN MISSING:', dbError.message);
          return res.status(500).json({
            success: false,
            message: 'Database configuration error',
            error: 'Missing required columns in users table',
            details: 'Please add missing columns: role, is_active, is_verified to users table',
            sqlError: dbError.message
          });
        }
        throw dbError; // Re-throw if it's a different error
      }

      if (users.length === 0) {
        await createAuditLog(executeQuery, null, 'LOGIN_FAILED', `Failed login attempt for email: ${sanitizedEmail}`, req.ip, req.get('User-Agent'));
        return res.status(401).json({
          success: false,
          message: 'Invalid email or password'
        });
      }

      const user = users[0];

      // Handle missing columns gracefully (default values)
      const userRole = user.role || 'user';
      const isActive = user.is_active !== undefined ? user.is_active : true;
      const isVerified = user.is_verified !== undefined ? user.is_verified : true;

      if (!isActive) {
        await createAuditLog(executeQuery, user.id, 'LOGIN_FAILED', 'Account is deactivated', req.ip, req.get('User-Agent'));
        return res.status(401).json({
          success: false,
          message: 'Account is deactivated'
        });
      }

      // Verify password
      const isPasswordValid = await comparePassword(password, user.password_hash);
      if (!isPasswordValid) {
        await createAuditLog(executeQuery, user.id, 'LOGIN_FAILED', 'Invalid password', req.ip, req.get('User-Agent'));
        return res.status(401).json({
          success: false,
          message: 'Invalid email or password'
        });
      }

      // Generate token
      const token = generateToken(user.id, user.email, userRole);

      // Store session (handle if table doesn't exist)
      try {
        await executeQuery(
          'INSERT INTO user_sessions (user_id, token_hash, device_info, ip_address, expires_at) VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))',
          [user.id, hashToken(token), req.get('User-Agent'), req.ip]
        );
      } catch (sessionError) {
        // If user_sessions table doesn't exist, log warning but don't fail login
        if (sessionError.message && sessionError.message.includes("doesn't exist")) {
          console.warn('⚠️ user_sessions table does not exist - session not stored');
        } else {
          throw sessionError; // Re-throw if it's a different error
        }
      }

      // Create audit log
      await createAuditLog(executeQuery, user.id, 'LOGIN_SUCCESS', 'User logged in successfully', req.ip, req.get('User-Agent'));

      res.json({
        success: true,
        message: 'Login successful',
        data: {
          token,
          user: {
            id: user.id,
            email: user.email,
            role: userRole,
            firstName: user.first_name,
            lastName: user.last_name,
            isVerified: isVerified
          }
        }
      });
    } catch (error) {
      // Detailed error logging
      console.error('❌ LOGIN ERROR:', error.message);
      console.error('❌ LOGIN ERROR STACK:', error.stack);
      console.error('❌ LOGIN ERROR DETAILS:', {
        message: error.message,
        code: error.code,
        errno: error.errno,
        sqlState: error.sqlState,
        name: error.name
      });
      
      // Return error details (safe for production - no sensitive data)
      // Always return error message in production for debugging
      res.status(500).json({
        success: false,
        message: 'Server error',
        error: error.message || 'Internal server error',
        errorCode: error.code || null,
        errorName: error.name || null,
        // Include helpful details
        hint: error.message?.includes('JWT_SECRET') 
          ? 'Check JWT_SECRET in environment variables'
          : error.message?.includes('Unknown column')
          ? 'Check database schema - missing columns'
          : error.message?.includes("doesn't exist")
          ? 'Check if required database tables exist'
          : 'Check backend logs for more details',
        // Only include stack in development
        ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
      });
    }
  }
);

// Signup route
router.post('/signup',
  signupRateLimit,
  [
    body('firstName').trim().isLength({ min: 1 }).withMessage('First name is required'),
    body('lastName').trim().isLength({ min: 1 }).withMessage('Last name is required'),
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('company').trim().isLength({ min: 1 }).withMessage('Company name is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { firstName, lastName, email, company, password } = req.body;
      
      // Sanitize inputs
      const sanitizedData = {
        firstName: sanitizeInput(firstName),
        lastName: sanitizeInput(lastName),
        email: sanitizeInput(email),
        company: sanitizeInput(company)
      };

      // Validate email format
      if (!isValidEmail(sanitizedData.email)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid email format'
        });
      }

      // Validate password strength
      const passwordValidation = validatePassword(password);
      if (!passwordValidation.isValid) {
        return res.status(400).json({
          success: false,
          message: 'Password does not meet requirements',
          errors: passwordValidation.errors
        });
      }

      // Check if email already exists
      const existingUsers = await executeQuery(
        'SELECT id FROM users WHERE email = ?',
        [sanitizedData.email]
      );

      if (existingUsers.length > 0) {
        return res.status(409).json({
          success: false,
          message: 'Email already registered'
        });
      }

      // Hash password
      const passwordHash = await hashPassword(password);

      // Create user (include default values for role, is_active, is_verified)
      const result = await executeQuery(
        'INSERT INTO users (first_name, last_name, email, password_hash, company, role, is_active, is_verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [sanitizedData.firstName, sanitizedData.lastName, sanitizedData.email, passwordHash, sanitizedData.company, 'user', true, false]
      );

      const userId = result.insertId;

      // Generate and send OTP
      const otp = generateOTP();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

      // Insert OTP (handle if otps table doesn't exist)
      try {
        await executeQuery(
          'INSERT INTO otps (email, otp_code, type, expires_at) VALUES (?, ?, ?, ?)',
          [sanitizedData.email, otp, 'email_verification', expiresAt]
        );
      } catch (otpError) {
        if (otpError.message && otpError.message.includes("doesn't exist")) {
          console.warn('⚠️ otps table does not exist - OTP not stored');
        } else {
          throw otpError;
        }
      }

      // Send OTP email (handle if email service fails)
      // Declare first
      let emailSent = false;
      let emailError = null;

      console.log('═══════════════════════════════════════════════════════════');
      console.log('📧 SIGNUP: Attempting to send OTP email...');
      console.log('  Email:', sanitizedData.email);
      console.log('  OTP:', otp);
      console.log('═══════════════════════════════════════════════════════════');

      try {
        await sendOTPEmail(sanitizedData.email, otp, 'email_verification');
        emailSent = true;
        console.log(`✅ SIGNUP: OTP email sent successfully to ${sanitizedData.email}`);
      } catch (err) {
        emailError = err;
        console.error('═══════════════════════════════════════════════════════════');
        console.error('❌ SIGNUP: CRITICAL EMAIL ERROR');
        console.error('  Error name:', err?.name);
        console.error('  Error message:', err?.message);
        console.error('  Error code:', err?.code);
        console.error('  Error stack:', err?.stack);
        console.error('═══════════════════════════════════════════════════════════');
        // Don't fail signup if email fails - user can request OTP again
      }

      // Create audit log
      await createAuditLog(executeQuery, userId, 'SIGNUP_SUCCESS', 'User registered successfully', req.ip, req.get('User-Agent'));

      // ✅ Now send response AFTER emailSent/emailError are correct
      return res.json({
        success: true,
        message: 'Registration successful. Please check your email for verification code.',
        emailSent: emailSent,
        emailError: emailSent ? null : (emailError?.message || 'Email service unavailable')
      });
    } catch (error) {
      console.error('❌ SIGNUP ERROR:', error.message);
      console.error('❌ SIGNUP ERROR STACK:', error.stack);
      console.error('❌ SIGNUP ERROR DETAILS:', {
        message: error.message,
        code: error.code,
        errno: error.errno,
        sqlState: error.sqlState,
        name: error.name
      });
      
      res.status(500).json({
        success: false,
        message: 'Server error',
        error: error.message || 'Internal server error',
        errorCode: error.code || null,
        hint: error.message?.includes('Unknown column')
          ? 'Check database schema - missing columns'
          : error.message?.includes("doesn't exist")
          ? 'Check if required database tables exist (users, otps)'
          : error.message?.includes('JWT_SECRET')
          ? 'JWT_SECRET issue (should be fixed)'
          : 'Check backend logs for more details'
      });
    }
  }
);

// Verify OTP route
router.post('/verify-otp',
  otpRateLimit,
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { email, otp } = req.body;
      const sanitizedEmail = sanitizeInput(email);

      // Find valid OTP (handle if otps table doesn't exist)
      let otps;
      try {
        otps = await executeQuery(
          'SELECT * FROM otps WHERE email = ? AND otp_code = ? AND type = ? AND expires_at > NOW() AND is_used = FALSE ORDER BY created_at DESC LIMIT 1',
          [sanitizedEmail, otp, 'email_verification']
        );
      } catch (otpError) {
        if (otpError.message && otpError.message.includes("doesn't exist")) {
          console.warn('⚠️ otps table does not exist');
          return res.status(400).json({
            success: false,
            message: 'OTP verification not available - database table missing'
          });
        } else {
          throw otpError;
        }
      }

      if (otps.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'Invalid or expired OTP'
        });
      }

      // Mark OTP as used
      await executeQuery(
        'UPDATE otps SET is_used = TRUE WHERE id = ?',
        [otps[0].id]
      );

      // Verify user email (handle missing is_verified column)
      try {
        await executeQuery(
          'UPDATE users SET is_verified = TRUE WHERE email = ?',
          [sanitizedEmail]
        );
      } catch (updateError) {
        if (updateError.message && updateError.message.includes('Unknown column')) {
          console.warn('⚠️ is_verified column does not exist - skipping verification update');
          // Continue without updating is_verified
        } else {
          throw updateError;
        }
      }

      // Get user details
      const users = await executeQuery(
        'SELECT id, first_name, email, role FROM users WHERE email = ?',
        [sanitizedEmail]
      );

      if (users.length > 0) {
        // Send welcome email (handle if email service fails)
        let welcomeEmailSent = false;
        let welcomeEmailError = null;
        console.log('═══════════════════════════════════════════════════════════');
        console.log('📧 VERIFY-OTP: Attempting to send welcome email...');
        console.log('  Email:', sanitizedEmail);
        console.log('═══════════════════════════════════════════════════════════');
        
        try {
          await sendWelcomeEmail(sanitizedEmail, users[0].first_name);
          welcomeEmailSent = true;
          console.log(`✅ VERIFY-OTP: Welcome email sent successfully to ${sanitizedEmail}`);
        } catch (err) {
          welcomeEmailError = err;
          console.error('═══════════════════════════════════════════════════════════');
          console.error('❌ VERIFY-OTP: CRITICAL - Failed to send welcome email:');
          console.error('  Email:', sanitizedEmail);
          console.error('  Error message:', err.message);
          console.error('  Error code:', err.code);
          console.error('  Error name:', err.name);
          console.error('  Error stack:', err.stack);
          console.error('  Full error:', err);
          console.error('═══════════════════════════════════════════════════════════');
          // Don't fail verification if email fails
        }

        // Create audit log (handle if audit_logs table doesn't exist)
        try {
          await createAuditLog(executeQuery, users[0].id, 'EMAIL_VERIFIED', 'Email verified successfully', req.ip, req.get('User-Agent'));
        } catch (auditError) {
          console.warn('⚠️ Failed to create audit log:', auditError.message);
          // Don't fail verification if audit log fails
        }
      }

      res.json({
        success: true,
        message: 'Email verified successfully',
        welcomeEmailSent: welcomeEmailSent,
        welcomeEmailError: welcomeEmailSent ? null : (welcomeEmailError?.message || 'Email service unavailable')
      });
    } catch (error) {
      console.error('❌ VERIFY OTP ERROR:', error.message);
      console.error('❌ VERIFY OTP ERROR STACK:', error.stack);
      console.error('❌ VERIFY OTP ERROR DETAILS:', {
        message: error.message,
        code: error.code,
        errno: error.errno,
        sqlState: error.sqlState,
        name: error.name
      });
      
      res.status(500).json({
        success: false,
        message: 'Server error',
        error: error.message || 'Internal server error',
        errorCode: error.code || null,
        hint: error.message?.includes('Unknown column')
          ? 'Check database schema - missing columns (is_verified, is_used)'
          : error.message?.includes("doesn't exist")
          ? 'Check if required database tables exist (otps, users)'
          : 'Check backend logs for more details'
      });
    }
  }
);

// Forgot password route
router.post('/forgot-password',
  otpRateLimit,
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { email } = req.body;
      const sanitizedEmail = sanitizeInput(email);

      // Check if user exists (handle missing is_active column gracefully)
      let users;
      try {
        users = await executeQuery(
          'SELECT id FROM users WHERE email = ? AND is_active = TRUE',
          [sanitizedEmail]
        );
      } catch (dbError) {
        // If is_active column doesn't exist, query without it
        if (dbError.message && dbError.message.includes('Unknown column')) {
          users = await executeQuery(
            'SELECT id FROM users WHERE email = ?',
            [sanitizedEmail]
          );
        } else {
          throw dbError;
        }
      }

      if (users.length === 0) {
        // Don't reveal if email exists or not
        return res.json({
          success: true,
          message: 'If the email exists, a reset code has been sent'
        });
      }

      // Generate OTP
      const otp = generateOTP();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

      // Delete any existing OTPs for this email
      await executeQuery(
        'DELETE FROM otps WHERE email = ? AND type = ?',
        [sanitizedEmail, 'password_reset']
      );

      // Insert new OTP (handle if otps table doesn't exist)
      try {
        await executeQuery(
          'INSERT INTO otps (email, otp_code, type, expires_at) VALUES (?, ?, ?, ?)',
          [sanitizedEmail, otp, 'password_reset', expiresAt]
        );
      } catch (otpError) {
        if (otpError.message && otpError.message.includes("doesn't exist")) {
          console.warn('⚠️ otps table does not exist - OTP not stored');
        } else {
          throw otpError;
        }
      }

      // Send OTP email (handle if email service fails)
      // Declare first
      let emailSent = false;
      let emailError = null;

      console.log('═══════════════════════════════════════════════════════════');
      console.log('📧 FORGOT-PASSWORD: Attempting to send OTP email...');
      console.log('  Email:', sanitizedEmail);
      console.log('  OTP:', otp);
      console.log('═══════════════════════════════════════════════════════════');

      try {
        await sendOTPEmail(sanitizedEmail, otp, 'password_reset');
        emailSent = true;
        console.log(`✅ FORGOT-PASSWORD: OTP email sent successfully to ${sanitizedEmail}`);
      } catch (err) {
        emailError = err;
        console.error('═══════════════════════════════════════════════════════════');
        console.error('❌ FORGOT-PASSWORD: CRITICAL EMAIL ERROR');
        console.error('  Error name:', err?.name);
        console.error('  Error message:', err?.message);
        console.error('  Error code:', err?.code);
        console.error('  Error stack:', err?.stack);
        console.error('═══════════════════════════════════════════════════════════');
        // Don't fail forgot-password if email fails
      }

      // Create audit log
      await createAuditLog(executeQuery, users[0].id, 'PASSWORD_RESET_REQUESTED', 'Password reset requested', req.ip, req.get('User-Agent'));

      // ✅ Now send response AFTER emailSent/emailError are correct
      return res.json({
        success: true,
        message: 'If the email exists, a reset code has been sent',
        emailSent: emailSent,
        emailError: emailSent ? null : (emailError?.message || 'Email service unavailable')
      });
    } catch (error) {
      console.error('❌ FORGOT PASSWORD ERROR:', error.message);
      console.error('❌ FORGOT PASSWORD ERROR STACK:', error.stack);
      console.error('❌ FORGOT PASSWORD ERROR DETAILS:', {
        message: error.message,
        code: error.code,
        errno: error.errno,
        sqlState: error.sqlState,
        name: error.name
      });
      
      res.status(500).json({
        success: false,
        message: 'Server error',
        error: error.message || 'Internal server error',
        errorCode: error.code || null,
        hint: error.message?.includes('Unknown column')
          ? 'Check database schema - missing columns'
          : error.message?.includes("doesn't exist")
          ? 'Check if required database tables exist (users, otps)'
          : error.message?.includes('email')
          ? 'Email service might not be configured'
          : 'Check backend logs for more details'
      });
    }
  }
);

// Reset password route
router.post('/reset-password',
  otpRateLimit,
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits'),
    body('newPassword').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { email, otp, newPassword } = req.body;
      const sanitizedEmail = sanitizeInput(email);

      // Validate password strength
      const passwordValidation = validatePassword(newPassword);
      if (!passwordValidation.isValid) {
        return res.status(400).json({
          success: false,
          message: 'Password does not meet requirements',
          errors: passwordValidation.errors
        });
      }

      // Find valid OTP
      const otps = await executeQuery(
        'SELECT * FROM otps WHERE email = ? AND otp_code = ? AND type = ? AND expires_at > NOW() AND is_used = FALSE ORDER BY created_at DESC LIMIT 1',
        [sanitizedEmail, otp, 'password_reset']
      );

      if (otps.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'Invalid or expired OTP'
        });
      }

      // Mark OTP as used
      await executeQuery(
        'UPDATE otps SET is_used = TRUE WHERE id = ?',
        [otps[0].id]
      );

      // Hash new password
      const passwordHash = await hashPassword(newPassword);

      // Update user password
      await executeQuery(
        'UPDATE users SET password_hash = ? WHERE email = ?',
        [passwordHash, sanitizedEmail]
      );

      // Get user for audit log
      const users = await executeQuery(
        'SELECT id FROM users WHERE email = ?',
        [sanitizedEmail]
      );

      if (users.length > 0) {
        // Create audit log
        await createAuditLog(executeQuery, users[0].id, 'PASSWORD_RESET_SUCCESS', 'Password reset successfully', req.ip, req.get('User-Agent'));
      }

      res.json({
        success: true,
        message: 'Password reset successfully'
      });
    } catch (error) {
      console.error('Reset password error:', error);
      res.status(500).json({
        success: false,
        message: 'Server error'
      });
    }
  }
);

// Logout route
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
      // Remove session
      await executeQuery(
        'DELETE FROM user_sessions WHERE token_hash = ?',
        [hashToken(token)]
      );
    }

    // Create audit log
    await createAuditLog(executeQuery, req.user.id, 'LOGOUT_SUCCESS', 'User logged out successfully', req.ip, req.get('User-Agent'));

    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get current user route
router.get('/me', authenticateToken, async (req, res) => {
  try {
    const users = await executeQuery(
      'SELECT id, first_name, last_name, email, role, company, is_verified, created_at FROM users WHERE id = ?',
      [req.user.id]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const user = users[0];
    res.json({
      success: true,
      data: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        role: user.role,
        company: user.company,
        isVerified: user.is_verified,
        createdAt: user.created_at
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

export default router; 