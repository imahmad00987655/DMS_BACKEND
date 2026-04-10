import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

// Lazy transporter creation - only create when credentials are available
let transporter = null;

// Function to get or create transporter with proper credential checks
const getTransporter = () => {
  console.log('🔧 Creating/Getting transporter...');
  console.log('  EMAIL_USER:', process.env.EMAIL_USER ? `${process.env.EMAIL_USER.substring(0, 3)}***` : '❌ NOT SET');
  console.log('  EMAIL_PASS:', process.env.EMAIL_PASS ? '✅ Set (length: ' + process.env.EMAIL_PASS.length + ')' : '❌ NOT SET');
  console.log('  EMAIL_FROM:', process.env.EMAIL_FROM || '❌ NOT SET');
  console.log('  EMAIL_HOST:', process.env.EMAIL_HOST || 'smtp.gmail.com (default)');
  console.log('  EMAIL_PORT:', process.env.EMAIL_PORT || '587 (default)');
  
  // Check if credentials exist
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.error('❌ CRITICAL: Cannot create transporter - EMAIL_USER or EMAIL_PASS missing!');
    throw new Error('Email service not configured: EMAIL_USER or EMAIL_PASS missing');
  }
  
  // If transporter doesn't exist or credentials changed, create new one
  if (!transporter) {
    console.log('📦 Creating new transporter instance...');
    transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST || 'smtp.gmail.com',
      port: Number(process.env.EMAIL_PORT) || 587,
      secure: Number(process.env.EMAIL_PORT) === 465, // true for 465, false for 587
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
      // Enhanced TLS options for Hostinger
      tls: {
        rejectUnauthorized: false, // Allow self-signed certificates (sometimes needed on shared hosting)
      },
      // Require TLS for port 587
      requireTLS: true,
      // Connection timeout
      connectionTimeout: 15000, // 15 seconds
      // Greeting timeout
      greetingTimeout: 15000,
      // Socket timeout
      socketTimeout: 15000,
      // Debug mode - ALWAYS ON for production to see email issues
      debug: true,
      logger: true
    });
    console.log('✅ Transporter created successfully');
  } else {
    console.log('♻️ Using existing transporter');
  }
  
  return transporter;
};

// Verify transporter configuration
export const verifyEmailConfig = async () => {
  try {
    console.log('🔍 Checking email configuration...');
    console.log('  EMAIL_HOST:', process.env.EMAIL_HOST || 'not set (using default: smtp.gmail.com)');
    console.log('  EMAIL_PORT:', process.env.EMAIL_PORT || 'not set (using default: 587)');
    console.log('  EMAIL_USER:', process.env.EMAIL_USER ? `${process.env.EMAIL_USER.substring(0, 3)}***` : '❌ NOT SET');
    console.log('  EMAIL_PASS:', process.env.EMAIL_PASS ? '✅ Set (length: ' + process.env.EMAIL_PASS.length + ')' : '❌ NOT SET');
    console.log('  EMAIL_FROM:', process.env.EMAIL_FROM || '❌ NOT SET');
    
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      console.error('❌ Email credentials missing - EMAIL_USER or EMAIL_PASS not set');
      return false;
    }
    
    const trans = getTransporter();
    console.log('🔐 Verifying SMTP connection...');
    await trans.verify();
    console.log('✅ Email service configured successfully - SMTP connection verified');
    return true;
  } catch (error) {
    console.error('❌ Email service configuration failed:');
    console.error('  Error message:', error.message);
    console.error('  Error code:', error.code);
    console.error('  Error command:', error.command);
    console.error('  Full error:', error);
    console.error('  Stack:', error.stack);
    
    // Common error messages and solutions
    if (error.message.includes('Invalid login')) {
      console.error('  💡 Solution: Check EMAIL_USER and EMAIL_PASS - credentials might be incorrect');
    } else if (error.message.includes('ECONNREFUSED') || error.message.includes('ETIMEDOUT')) {
      console.error('  💡 Solution: Check EMAIL_HOST and EMAIL_PORT - SMTP server might be unreachable or port blocked');
    } else if (error.message.includes('self signed certificate')) {
      console.error('  💡 Solution: TLS certificate issue - might need to allow self-signed certs');
    }
    
    return false;
  }
};

// Send OTP email
export const sendOTPEmail = async (email, otp, type = 'verification') => {
  console.log('═══════════════════════════════════════════════════════════');
  console.log('📧 sendOTPEmail CALLED');
  console.log('  Email:', email);
  console.log('  OTP:', otp);
  console.log('  Type:', type);
  console.log('═══════════════════════════════════════════════════════════');
  
  try {
    // CRITICAL: Check email credentials BEFORE attempting to send
    console.log('🔍 Step 1: Pre-flight check - Verifying email credentials...');
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS || !process.env.EMAIL_FROM) {
      const missing = [];
      if (!process.env.EMAIL_USER) missing.push('EMAIL_USER');
      if (!process.env.EMAIL_PASS) missing.push('EMAIL_PASS');
      if (!process.env.EMAIL_FROM) missing.push('EMAIL_FROM');
      
      console.error('❌ CRITICAL: Email environment variables missing:', missing.join(', '));
      console.error('  EMAIL_USER:', process.env.EMAIL_USER ? '✅ Set' : '❌ NOT SET');
      console.error('  EMAIL_PASS:', process.env.EMAIL_PASS ? '✅ Set' : '❌ NOT SET');
      console.error('  EMAIL_FROM:', process.env.EMAIL_FROM ? '✅ Set' : '❌ NOT SET');
      throw new Error(`Email service not configured: Missing ${missing.join(', ')}. Please set these in Hostinger environment variables.`);
    }
    
    console.log('✅ Step 1: Email credentials check passed');
    console.log('  EMAIL_USER:', process.env.EMAIL_USER.substring(0, 3) + '***');
    console.log('  EMAIL_FROM:', process.env.EMAIL_FROM);
    
    const subject = type === 'password_reset' 
      ? 'Password Reset Verification Code' 
      : 'Email Verification Code';
    
    const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; text-align: center;">
          <h1 style="margin: 0; font-size: 28px;">AccuFlow</h1>
          <p style="margin: 10px 0 0 0; opacity: 0.9;">Enterprise Accounting System</p>
        </div>
        
        <div style="background: white; padding: 30px; border: 1px solid #e1e5e9; border-radius: 0 0 10px 10px;">
          <h2 style="color: #333; margin-bottom: 20px;">${subject}</h2>
          
          <p style="color: #666; line-height: 1.6; margin-bottom: 25px;">
            ${type === 'password_reset' 
              ? 'You have requested to reset your password. Use the verification code below to complete the process.'
              : 'Thank you for signing up! Please use the verification code below to verify your email address.'
            }
          </p>
          
          <div style="background: #f8f9fa; border: 2px solid #e9ecef; border-radius: 8px; padding: 20px; text-align: center; margin: 25px 0;">
            <div style="font-size: 32px; font-weight: bold; color: #495057; letter-spacing: 8px; font-family: 'Courier New', monospace;">
              ${otp}
            </div>
          </div>
          
          <p style="color: #666; font-size: 14px; margin-top: 25px;">
            This code will expire in 10 minutes. If you didn't request this, please ignore this email.
          </p>
          
          <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e9ecef;">
            <p style="color: #999; font-size: 12px; margin: 0;">
              © 2024 AccuFlow. All rights reserved.
            </p>
          </div>
        </div>
      </div>
    `;

    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: subject,
      html: htmlContent,
    };

    console.log('✅ Step 2: Email content prepared');
    console.log(`📧 Step 3: Attempting to send OTP email to ${email}...`);
    console.log(`  From: ${process.env.EMAIL_FROM}`);
    console.log(`  Subject: ${subject}`);
    console.log(`  Host: ${process.env.EMAIL_HOST || 'smtp.gmail.com'}`);
    console.log(`  Port: ${process.env.EMAIL_PORT || 587}`);
    
    // Get transporter (will create if needed)
    console.log('🔧 Step 4: Getting transporter...');
    const trans = getTransporter();
    console.log('✅ Step 4: Transporter obtained');
    
    // Try to send email
    console.log('📤 Step 5: Sending email via SMTP...');
    console.log('  Mail options:', {
      from: mailOptions.from,
      to: mailOptions.to,
      subject: mailOptions.subject,
      htmlLength: mailOptions.html.length
    });
    
    const result = await trans.sendMail(mailOptions);
    
    console.log('═══════════════════════════════════════════════════════════');
    console.log(`✅ SUCCESS: OTP email sent successfully to ${email}`);
    console.log(`  Message ID: ${result.messageId}`);
    console.log(`  Response: ${result.response}`);
    console.log('═══════════════════════════════════════════════════════════');
    return result;
  } catch (error) {
    console.error('═══════════════════════════════════════════════════════════');
    console.error('❌ FAILED: OTP email sending failed');
    console.error('  To:', email);
    console.error('  OTP:', otp);
    console.error('  Error message:', error.message);
    console.error('  Error code:', error.code);
    console.error('  Error name:', error.name);
    console.error('  Error command:', error.command);
    console.error('  Full error object:', JSON.stringify(error, Object.getOwnPropertyNames(error)));
    console.error('  Stack trace:', error.stack);
    
    // More detailed error information
    if (error.response) {
      console.error('  SMTP Response:', error.response);
    }
    if (error.responseCode) {
      console.error('  SMTP Response Code:', error.responseCode);
    }
    if (error.code === 'EAUTH') {
      console.error('  💡 AUTH ERROR: Check EMAIL_USER and EMAIL_PASS - might be incorrect');
    } else if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT') {
      console.error('  💡 CONNECTION ERROR: Check EMAIL_HOST and EMAIL_PORT - might be blocked');
    }
    console.error('═══════════════════════════════════════════════════════════');
    
    throw new Error(`Failed to send email: ${error.message}`);
  }
};

// Send welcome email
export const sendWelcomeEmail = async (email, firstName) => {
  try {
    const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; text-align: center;">
          <h1 style="margin: 0; font-size: 28px;">AccuFlow</h1>
          <p style="margin: 10px 0 0 0; opacity: 0.9;">Enterprise Accounting System</p>
        </div>
        
        <div style="background: white; padding: 30px; border: 1px solid #e1e5e9; border-radius: 0 0 10px 10px;">
          <h2 style="color: #333; margin-bottom: 20px;">Welcome to AccuFlow!</h2>
          
          <p style="color: #666; line-height: 1.6; margin-bottom: 20px;">
            Hi ${firstName},
          </p>
          
          <p style="color: #666; line-height: 1.6; margin-bottom: 20px;">
            Welcome to AccuFlow! Your account has been successfully created and verified. You can now access all the features of our enterprise accounting system.
          </p>
          
          <div style="background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px; padding: 20px; margin: 25px 0;">
            <h3 style="color: #495057; margin-top: 0;">What you can do now:</h3>
            <ul style="color: #666; line-height: 1.6;">
              <li>Access your dashboard</li>
              <li>Manage your financial data</li>
              <li>Generate reports</li>
              <li>Track your business metrics</li>
            </ul>
          </div>
          
          <p style="color: #666; line-height: 1.6;">
            If you have any questions or need assistance, please don't hesitate to contact our support team.
          </p>
          
          <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e9ecef;">
            <p style="color: #999; font-size: 12px; margin: 0;">
              © 2024 AccuFlow. All rights reserved.
            </p>
          </div>
        </div>
      </div>
    `;

    // CRITICAL: Check email credentials BEFORE attempting to send
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS || !process.env.EMAIL_FROM) {
      const missing = [];
      if (!process.env.EMAIL_USER) missing.push('EMAIL_USER');
      if (!process.env.EMAIL_PASS) missing.push('EMAIL_PASS');
      if (!process.env.EMAIL_FROM) missing.push('EMAIL_FROM');
      throw new Error(`Email service not configured: Missing ${missing.join(', ')}`);
    }

    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: 'Welcome to AccuFlow!',
      html: htmlContent,
    };

    console.log(`📧 Attempting to send welcome email to ${email}...`);
    const trans = getTransporter();
    const result = await trans.sendMail(mailOptions);
    console.log(`✅ Welcome email sent to ${email}`);
    return result;
  } catch (error) {
    console.error('❌ Failed to send welcome email:', error.message);
    throw new Error(`Failed to send welcome email: ${error.message}`);
  }
};

export default getTransporter; 