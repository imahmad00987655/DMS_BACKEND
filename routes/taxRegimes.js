import express from 'express';
import { executeQuery } from '../config/database.js';
import { authenticateToken } from '../middleware/auth.js';

const router = express.Router();

// Get all tax regimes
router.get('/', authenticateToken, async (req, res) => {
  try {
    const regimes = await executeQuery(`
      SELECT 
        tr.*,
        u.first_name,
        u.last_name
      FROM tax_regimes tr
      LEFT JOIN users u ON tr.created_by = u.id
      ORDER BY tr.created_at DESC
    `);
    
    res.json({
      success: true,
      data: regimes
    });
  } catch (error) {
    console.error('Error fetching tax regimes:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch tax regimes',
      error: error.message
    });
  }
});

// Get single tax regime by ID
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const regimes = await executeQuery(`
      SELECT 
        tr.*,
        u.first_name,
        u.last_name
      FROM tax_regimes tr
      LEFT JOIN users u ON tr.created_by = u.id
      WHERE tr.id = ?
    `, [id]);
    
    if (regimes.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Tax regime not found'
      });
    }
    
    res.json({
      success: true,
      data: regimes[0]
    });
  } catch (error) {
    console.error('Error fetching tax regime:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch tax regime',
      error: error.message
    });
  }
});

// Create new tax regime
router.post('/', authenticateToken, async (req, res) => {
  try {
    const {
      regime_code,
      regime_name,
      regime_type,
      tax_authority,
      effective_date,
      end_date,
      status = 'ACTIVE'
    } = req.body;
    
    // Validate required fields
    if (!regime_code || !regime_name || !regime_type || !effective_date) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields: regime_code, regime_name, regime_type, effective_date'
      });
    }
    
    // Check if regime code already exists
    const existingRegime = await executeQuery(
      'SELECT id FROM tax_regimes WHERE regime_code = ?',
      [regime_code]
    );
    
    if (existingRegime.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Tax regime code already exists'
      });
    }
    
    const result = await executeQuery(`
      INSERT INTO tax_regimes (
        regime_code, regime_name, regime_type, tax_authority, 
        effective_date, end_date, status, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      regime_code, regime_name, regime_type, tax_authority,
      effective_date, end_date, status, req.user.id
    ]);
    
    // Fetch the created regime
    const newRegime = await executeQuery(`
      SELECT 
        tr.*,
        u.first_name,
        u.last_name
      FROM tax_regimes tr
      LEFT JOIN users u ON tr.created_by = u.id
      WHERE tr.id = ?
    `, [result.insertId]);
    
    res.status(201).json({
      success: true,
      message: 'Tax regime created successfully',
      data: newRegime[0]
    });
  } catch (error) {
    console.error('Error creating tax regime:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create tax regime',
      error: error.message
    });
  }
});

// Update tax regime
router.put('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      regime_code,
      regime_name,
      regime_type,
      tax_authority,
      effective_date,
      end_date,
      status
    } = req.body;
    
    // Check if regime exists
    const existingRegime = await executeQuery(
      'SELECT id FROM tax_regimes WHERE id = ?',
      [id]
    );
    
    if (existingRegime.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Tax regime not found'
      });
    }
    
    // Check if regime code already exists (excluding current record)
    if (regime_code) {
      const duplicateRegime = await executeQuery(
        'SELECT id FROM tax_regimes WHERE regime_code = ? AND id != ?',
        [regime_code, id]
      );
      
      if (duplicateRegime.length > 0) {
        return res.status(400).json({
          success: false,
          message: 'Tax regime code already exists'
        });
      }
    }
    
    await executeQuery(`
      UPDATE tax_regimes SET
        regime_code = COALESCE(?, regime_code),
        regime_name = COALESCE(?, regime_name),
        regime_type = COALESCE(?, regime_type),
        tax_authority = COALESCE(?, tax_authority),
        effective_date = COALESCE(?, effective_date),
        end_date = ?,
        status = COALESCE(?, status),
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `, [
      regime_code, regime_name, regime_type, tax_authority,
      effective_date, end_date, status, id
    ]);
    
    // Fetch the updated regime
    const updatedRegime = await executeQuery(`
      SELECT 
        tr.*,
        u.first_name,
        u.last_name
      FROM tax_regimes tr
      LEFT JOIN users u ON tr.created_by = u.id
      WHERE tr.id = ?
    `, [id]);
    
    res.json({
      success: true,
      message: 'Tax regime updated successfully',
      data: updatedRegime[0]
    });
  } catch (error) {
    console.error('Error updating tax regime:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update tax regime',
      error: error.message
    });
  }
});

// Delete tax regime
router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check if regime exists
    const existingRegime = await executeQuery(
      'SELECT id FROM tax_regimes WHERE id = ?',
      [id]
    );
    
    if (existingRegime.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Tax regime not found'
      });
    }
    
    // Check if regime is being used by tax types
    const dependentTypes = await executeQuery(
      'SELECT id FROM tax_types WHERE regime_id = ?',
      [id]
    );
    
    if (dependentTypes.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete tax regime. It is being used by tax types.'
      });
    }
    
    await executeQuery('DELETE FROM tax_regimes WHERE id = ?', [id]);
    
    res.json({
      success: true,
      message: 'Tax regime deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting tax regime:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete tax regime',
      error: error.message
    });
  }
});

export default router;
