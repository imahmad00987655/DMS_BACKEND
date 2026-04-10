import express from 'express';
import { executeQuery } from '../config/database.js';
import { authenticateToken } from '../middleware/auth.js';

const router = express.Router();

// Get all tax rates
router.get('/', authenticateToken, async (req, res) => {
  try {
    const taxRates = await executeQuery(`
      SELECT 
        tr.*,
        tt.tax_type_name,
        u.first_name,
        u.last_name
      FROM tax_rates tr
      LEFT JOIN tax_types tt ON tr.tax_type_id = tt.id
      LEFT JOIN users u ON tr.created_by = u.id
      ORDER BY tr.created_at DESC
    `);
    
    res.json({
      success: true,
      data: taxRates
    });
  } catch (error) {
    console.error('Error fetching tax rates:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch tax rates',
      error: error.message
    });
  }
});

// Get single tax rate by ID
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const taxRates = await executeQuery(`
      SELECT 
        tr.*,
        tt.tax_type_name,
        u.first_name,
        u.last_name
      FROM tax_rates tr
      LEFT JOIN tax_types tt ON tr.tax_type_id = tt.id
      LEFT JOIN users u ON tr.created_by = u.id
      WHERE tr.id = ?
    `, [id]);
    
    if (taxRates.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Tax rate not found'
      });
    }
    
    res.json({
      success: true,
      data: taxRates[0]
    });
  } catch (error) {
    console.error('Error fetching tax rate:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch tax rate',
      error: error.message
    });
  }
});

// Create new tax rate
router.post('/', authenticateToken, async (req, res) => {
  try {
    console.log('Received tax rate creation request:', JSON.stringify(req.body, null, 2));
    
    const {
      rate_code,
      tax_percentage,
      tax_type_id,
      effective_date,
      end_date,
      is_recoverable = false,
      is_inclusive = false,
      is_self_assessable = false,
      status = 'ACTIVE'
    } = req.body;
    
    // Validate required fields
    // Check for empty strings, null, undefined, or NaN values
    if (!rate_code || (typeof rate_code === 'string' && rate_code.trim() === '')) {
      console.log('Validation failed: rate_code is missing or empty');
      return res.status(400).json({
        success: false,
        message: 'Missing required field: rate_code'
      });
    }
    
    if (tax_percentage === null || tax_percentage === undefined || isNaN(Number(tax_percentage))) {
      console.log('Validation failed: tax_percentage is missing or invalid', { tax_percentage, type: typeof tax_percentage });
      return res.status(400).json({
        success: false,
        message: 'Missing required field: tax_percentage'
      });
    }
    
    if (!tax_type_id || isNaN(Number(tax_type_id))) {
      console.log('Validation failed: tax_type_id is missing or invalid', { tax_type_id, type: typeof tax_type_id });
      return res.status(400).json({
        success: false,
        message: 'Missing required field: tax_type_id'
      });
    }
    
    if (!effective_date || (typeof effective_date === 'string' && effective_date.trim() === '')) {
      console.log('Validation failed: effective_date is missing or empty', { effective_date, type: typeof effective_date });
      return res.status(400).json({
        success: false,
        message: 'Missing required field: effective_date'
      });
    }
    
    // Check if rate code already exists
    const existingRate = await executeQuery(
      'SELECT id FROM tax_rates WHERE rate_code = ?',
      [rate_code]
    );
    
    if (existingRate.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Tax rate code already exists'
      });
    }
    
    // Verify tax type exists
    const taxType = await executeQuery(
      'SELECT id FROM tax_types WHERE id = ?',
      [tax_type_id]
    );
    
    if (taxType.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid tax type ID'
      });
    }
    
    const result = await executeQuery(`
      INSERT INTO tax_rates (
        rate_code, tax_percentage, tax_type_id, effective_date, end_date,
        is_recoverable, is_inclusive, is_self_assessable, status, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      rate_code, tax_percentage, tax_type_id, effective_date, end_date,
      is_recoverable, is_inclusive, is_self_assessable, status, req.user.id
    ]);
    
    // Fetch the created tax rate
    const newTaxRate = await executeQuery(`
      SELECT 
        tr.*,
        tt.tax_type_name,
        u.first_name,
        u.last_name
      FROM tax_rates tr
      LEFT JOIN tax_types tt ON tr.tax_type_id = tt.id
      LEFT JOIN users u ON tr.created_by = u.id
      WHERE tr.id = ?
    `, [result.insertId]);
    
    res.status(201).json({
      success: true,
      message: 'Tax rate created successfully',
      data: newTaxRate[0]
    });
  } catch (error) {
    console.error('Error creating tax rate:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create tax rate',
      error: error.message
    });
  }
});

// Update tax rate
router.put('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      rate_code,
      tax_percentage,
      tax_type_id,
      effective_date,
      end_date,
      is_recoverable,
      is_inclusive,
      is_self_assessable,
      status
    } = req.body;
    
    // Check if tax rate exists
    const existingRate = await executeQuery(
      'SELECT id FROM tax_rates WHERE id = ?',
      [id]
    );
    
    if (existingRate.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Tax rate not found'
      });
    }
    
    // Check if rate code already exists (excluding current record)
    if (rate_code) {
      const duplicateRate = await executeQuery(
        'SELECT id FROM tax_rates WHERE rate_code = ? AND id != ?',
        [rate_code, id]
      );
      
      if (duplicateRate.length > 0) {
        return res.status(400).json({
          success: false,
          message: 'Tax rate code already exists'
        });
      }
    }
    
    // Verify tax type exists if provided
    if (tax_type_id) {
      const taxType = await executeQuery(
        'SELECT id FROM tax_types WHERE id = ?',
        [tax_type_id]
      );
      
      if (taxType.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'Invalid tax type ID'
        });
      }
    }
    
    await executeQuery(`
      UPDATE tax_rates SET
        rate_code = COALESCE(?, rate_code),
        tax_percentage = COALESCE(?, tax_percentage),
        tax_type_id = COALESCE(?, tax_type_id),
        effective_date = COALESCE(?, effective_date),
        end_date = ?,
        is_recoverable = COALESCE(?, is_recoverable),
        is_inclusive = COALESCE(?, is_inclusive),
        is_self_assessable = COALESCE(?, is_self_assessable),
        status = COALESCE(?, status),
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `, [
      rate_code, tax_percentage, tax_type_id, effective_date, end_date,
      is_recoverable, is_inclusive, is_self_assessable, status, id
    ]);
    
    // Fetch the updated tax rate
    const updatedTaxRate = await executeQuery(`
      SELECT 
        tr.*,
        tt.tax_type_name,
        u.first_name,
        u.last_name
      FROM tax_rates tr
      LEFT JOIN tax_types tt ON tr.tax_type_id = tt.id
      LEFT JOIN users u ON tr.created_by = u.id
      WHERE tr.id = ?
    `, [id]);
    
    res.json({
      success: true,
      message: 'Tax rate updated successfully',
      data: updatedTaxRate[0]
    });
  } catch (error) {
    console.error('Error updating tax rate:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update tax rate',
      error: error.message
    });
  }
});

// Delete tax rate
router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check if tax rate exists
    const existingRate = await executeQuery(
      'SELECT id FROM tax_rates WHERE id = ?',
      [id]
    );
    
    if (existingRate.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Tax rate not found'
      });
    }
    
    await executeQuery('DELETE FROM tax_rates WHERE id = ?', [id]);
    
    res.json({
      success: true,
      message: 'Tax rate deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting tax rate:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete tax rate',
      error: error.message
    });
  }
});

export default router;
