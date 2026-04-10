import express from 'express';
import { executeQuery } from '../config/database.js';
import { authenticateToken } from '../middleware/auth.js';

const router = express.Router();

// Get all tax types
router.get('/', authenticateToken, async (req, res) => {
  try {
    const taxTypes = await executeQuery(`
      SELECT 
        tt.*,
        tr.regime_name,
        u.first_name,
        u.last_name
      FROM tax_types tt
      LEFT JOIN tax_regimes tr ON tt.regime_id = tr.id
      LEFT JOIN users u ON tt.created_by = u.id
      ORDER BY tt.created_at DESC
    `);
    
    res.json({
      success: true,
      data: taxTypes
    });
  } catch (error) {
    console.error('Error fetching tax types:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch tax types',
      error: error.message
    });
  }
});

// Get single tax type by ID
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const taxTypes = await executeQuery(`
      SELECT 
        tt.*,
        tr.regime_name,
        u.first_name,
        u.last_name
      FROM tax_types tt
      LEFT JOIN tax_regimes tr ON tt.regime_id = tr.id
      LEFT JOIN users u ON tt.created_by = u.id
      WHERE tt.id = ?
    `, [id]);
    
    if (taxTypes.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Tax type not found'
      });
    }
    
    res.json({
      success: true,
      data: taxTypes[0]
    });
  } catch (error) {
    console.error('Error fetching tax type:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch tax type',
      error: error.message
    });
  }
});

// Create new tax type
router.post('/', authenticateToken, async (req, res) => {
  try {
    const {
      tax_type_code,
      tax_type_name,
      regime_id,
      operating_unit,
      ledger,
      liability_account,
      input_tax_account,
      output_tax_account,
      rounding_account,
      is_withholding_tax = false,
      is_self_assessed = false,
      is_recoverable = false,
      status = 'ACTIVE'
    } = req.body;
    
    // Validate required fields
    if (!tax_type_code || !tax_type_name || !regime_id) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields: tax_type_code, tax_type_name, regime_id'
      });
    }
    
    // Check if tax type code already exists
    const existingType = await executeQuery(
      'SELECT id FROM tax_types WHERE tax_type_code = ?',
      [tax_type_code]
    );
    
    if (existingType.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Tax type code already exists'
      });
    }
    
    // Verify regime exists
    const regime = await executeQuery(
      'SELECT id FROM tax_regimes WHERE id = ?',
      [regime_id]
    );
    
    if (regime.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid regime ID'
      });
    }
    
    const result = await executeQuery(`
      INSERT INTO tax_types (
        tax_type_code, tax_type_name, regime_id, operating_unit, ledger,
        liability_account, input_tax_account, output_tax_account, rounding_account, is_withholding_tax, is_self_assessed,
        is_recoverable, status, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      tax_type_code, tax_type_name, regime_id, operating_unit, ledger,
      liability_account, input_tax_account, output_tax_account, rounding_account, is_withholding_tax, is_self_assessed,
      is_recoverable, status, req.user.id
    ]);
    
    // Fetch the created tax type
    const newTaxType = await executeQuery(`
      SELECT 
        tt.*,
        tr.regime_name,
        u.first_name,
        u.last_name
      FROM tax_types tt
      LEFT JOIN tax_regimes tr ON tt.regime_id = tr.id
      LEFT JOIN users u ON tt.created_by = u.id
      WHERE tt.id = ?
    `, [result.insertId]);
    
    res.status(201).json({
      success: true,
      message: 'Tax type created successfully',
      data: newTaxType[0]
    });
  } catch (error) {
    console.error('Error creating tax type:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create tax type',
      error: error.message
    });
  }
});

// Update tax type
router.put('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      tax_type_code,
      tax_type_name,
      regime_id,
      operating_unit,
      ledger,
      liability_account,
      input_tax_account,
      output_tax_account,
      rounding_account,
      is_withholding_tax,
      is_self_assessed,
      is_recoverable,
      status
    } = req.body;
    
    // Check if tax type exists
    const existingType = await executeQuery(
      'SELECT id FROM tax_types WHERE id = ?',
      [id]
    );
    
    if (existingType.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Tax type not found'
      });
    }
    
    // Check if tax type code already exists (excluding current record)
    if (tax_type_code) {
      const duplicateType = await executeQuery(
        'SELECT id FROM tax_types WHERE tax_type_code = ? AND id != ?',
        [tax_type_code, id]
      );
      
      if (duplicateType.length > 0) {
        return res.status(400).json({
          success: false,
          message: 'Tax type code already exists'
        });
      }
    }
    
    // Verify regime exists if provided
    if (regime_id) {
      const regime = await executeQuery(
        'SELECT id FROM tax_regimes WHERE id = ?',
        [regime_id]
      );
      
      if (regime.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'Invalid regime ID'
        });
      }
    }
    
    await executeQuery(`
      UPDATE tax_types SET
        tax_type_code = COALESCE(?, tax_type_code),
        tax_type_name = COALESCE(?, tax_type_name),
        regime_id = COALESCE(?, regime_id),
        operating_unit = COALESCE(?, operating_unit),
        ledger = COALESCE(?, ledger),
        liability_account = COALESCE(?, liability_account),
        input_tax_account = COALESCE(?, input_tax_account),
        output_tax_account = COALESCE(?, output_tax_account),
        rounding_account = COALESCE(?, rounding_account),
        is_withholding_tax = COALESCE(?, is_withholding_tax),
        is_self_assessed = COALESCE(?, is_self_assessed),
        is_recoverable = COALESCE(?, is_recoverable),
        status = COALESCE(?, status),
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `, [
      tax_type_code, tax_type_name, regime_id, operating_unit, ledger,
      liability_account, input_tax_account, output_tax_account, rounding_account, is_withholding_tax, is_self_assessed,
      is_recoverable, status, id
    ]);
    
    // Fetch the updated tax type
    const updatedTaxType = await executeQuery(`
      SELECT 
        tt.*,
        tr.regime_name,
        u.first_name,
        u.last_name
      FROM tax_types tt
      LEFT JOIN tax_regimes tr ON tt.regime_id = tr.id
      LEFT JOIN users u ON tt.created_by = u.id
      WHERE tt.id = ?
    `, [id]);
    
    res.json({
      success: true,
      message: 'Tax type updated successfully',
      data: updatedTaxType[0]
    });
  } catch (error) {
    console.error('Error updating tax type:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update tax type',
      error: error.message
    });
  }
});

// Delete tax type
router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check if tax type exists
    const existingType = await executeQuery(
      'SELECT id FROM tax_types WHERE id = ?',
      [id]
    );
    
    if (existingType.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Tax type not found'
      });
    }
    
    // Check if tax type is being used by tax rates
    const dependentRates = await executeQuery(
      'SELECT id FROM tax_rates WHERE tax_type_id = ?',
      [id]
    );
    
    if (dependentRates.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete tax type. It is being used by tax rates.'
      });
    }
    
    await executeQuery('DELETE FROM tax_types WHERE id = ?', [id]);
    
    res.json({
      success: true,
      message: 'Tax type deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting tax type:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete tax type',
      error: error.message
    });
  }
});

export default router;
