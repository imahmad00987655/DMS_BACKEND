import express from 'express';
import { executeQuery } from '../config/database.js';
import { authenticateToken } from '../middleware/auth.js';
import upload from '../config/uploadBase64.js';

const router = express.Router();

// Get current user profile
router.get('/me', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    console.log('Fetching profile for user ID:', userId); // Debug log
    
    const users = await executeQuery(
      'SELECT id, first_name, last_name, email, phone, company, profile_image, role, created_at FROM users WHERE id = ?',
      [userId]
    );
    
    console.log('Users found:', users?.length || 0); // Debug log
    
    if (!users || users.length === 0) {
      console.error('User not found with ID:', userId);
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    const user = users[0];
    console.log('User data before processing:', user); // Debug log
    
    // If profile_image exists and is not already a data URL, it should be base64
    // The frontend will handle displaying base64 images as data URLs
    // No conversion needed - base64 is already stored in database
    
    console.log('Sending user data:', user); // Debug log
    res.json({ success: true, data: user });
  } catch (error) {
    console.error('Error fetching profile:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update profile (without image)
router.put('/me', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { first_name, last_name, email, phone, company } = req.body;
    
    // Check if email is being changed and if it's already taken by another user
    if (email) {
      const existingUsers = await executeQuery(
        'SELECT id FROM users WHERE email = ? AND id != ?',
        [email, userId]
      );
      
      if (existingUsers && existingUsers.length > 0) {
        return res.status(400).json({ 
          success: false, 
          error: 'Email already exists' 
        });
      }
    }
    
    // Build update query dynamically
    const updates = [];
    const values = [];
    
    if (first_name !== undefined) {
      updates.push('first_name = ?');
      values.push(first_name);
    }
    if (last_name !== undefined) {
      updates.push('last_name = ?');
      values.push(last_name);
    }
    if (email !== undefined) {
      updates.push('email = ?');
      values.push(email);
    }
    if (phone !== undefined) {
      updates.push('phone = ?');
      values.push(phone);
    }
    if (company !== undefined) {
      updates.push('company = ?');
      values.push(company);
    }
    
    if (updates.length === 0) {
      return res.status(400).json({ success: false, error: 'No fields to update' });
    }
    
    values.push(userId);
    
    await executeQuery(
      `UPDATE users SET ${updates.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
      values
    );
    
    res.json({ success: true, message: 'Profile updated successfully' });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Upload profile image as base64
router.post('/me/upload-image', authenticateToken, upload.single('profileImage'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No image file provided' });
    }
    
    const userId = req.user.id;
    
    // Convert image buffer to base64
    const imageBuffer = req.file.buffer;
    const base64Image = imageBuffer.toString('base64');
    
    // Get the MIME type from the uploaded file
    const mimeType = req.file.mimetype || 'image/jpeg';
    
    // Create data URL format: data:image/jpeg;base64,/9j/4AAQ...
    const base64DataUrl = `data:${mimeType};base64,${base64Image}`;
    
    // Update user profile with base64 image data
    await executeQuery(
      'UPDATE users SET profile_image = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [base64DataUrl, userId]
    );
    
    res.json({ 
      success: true, 
      message: 'Profile image uploaded successfully',
      data: {
        profile_image: base64DataUrl
      }
    });
  } catch (error) {
    console.error('Error uploading profile image:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete profile image
router.delete('/me/image', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Get current image to check if it exists
    const users = await executeQuery(
      'SELECT profile_image FROM users WHERE id = ?',
      [userId]
    );
    
    const hasImage = users[0]?.profile_image;
    
    if (!hasImage) {
      return res.status(404).json({ success: false, error: 'No profile image found' });
    }
    
    // Update user record to remove base64 image data
    await executeQuery(
      'UPDATE users SET profile_image = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [userId]
    );
    
    res.json({ success: true, message: 'Profile image deleted successfully' });
  } catch (error) {
    console.error('Error deleting profile image:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

export default router;

