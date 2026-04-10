import express from 'express';
import pool from '../config/database.js';

const router = express.Router();

// GET all assets
router.get('/', async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM assets');
    res.json({ data: rows });
  } catch (error) {
    console.error('Error fetching assets:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST create new asset
router.post('/', async (req, res) => {
  try {
    const {
      asset_id, name, category, sub_category, value, purchase_date, location, department,
      depreciation_method, useful_life, salvage_value, vendor, serial_number, warranty_expiry,
      condition, description, insurance_value, maintenance_schedule
    } = req.body;

    const sql = `
      INSERT INTO assets (
        asset_id, name, category, sub_category, value, purchase_date, location, department,
        depreciation_method, useful_life, salvage_value, vendor, serial_number, warranty_expiry,
        \`condition\`, description, insurance_value, maintenance_schedule
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const params = [
      asset_id, name, category, sub_category, value, purchase_date, location, department,
      depreciation_method, useful_life, salvage_value, vendor, serial_number, warranty_expiry,
      condition, description, insurance_value, maintenance_schedule
    ];

    const [result] = await pool.execute(sql, params);
    res.json({ id: result.insertId });
  } catch (error) {
    console.error('Error creating asset:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET single asset by ID
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await pool.execute('SELECT * FROM assets WHERE id = ?', [id]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Asset not found' });
    }
    
    res.json({ data: rows[0] });
  } catch (error) {
    console.error('Error fetching asset:', error);
    res.status(500).json({ error: error.message });
  }
});

// PUT update asset
router.put('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const {
      asset_id, name, category, sub_category, value, purchase_date, location, department,
      depreciation_method, useful_life, salvage_value, vendor, serial_number, warranty_expiry,
      condition, description, insurance_value, maintenance_schedule
    } = req.body;

    const sql = `
      UPDATE assets SET 
        asset_id = ?, name = ?, category = ?, sub_category = ?, value = ?, purchase_date = ?, 
        location = ?, department = ?, depreciation_method = ?, useful_life = ?, 
        salvage_value = ?, vendor = ?, serial_number = ?, warranty_expiry = ?, 
        \`condition\` = ?, description = ?, insurance_value = ?, maintenance_schedule = ?,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `;
    const params = [
      asset_id, name, category, sub_category, value, purchase_date, location, department,
      depreciation_method, useful_life, salvage_value, vendor, serial_number, warranty_expiry,
      condition, description, insurance_value, maintenance_schedule, id
    ];

    const [result] = await pool.execute(sql, params);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Asset not found' });
    }
    res.json({ message: 'Asset updated successfully' });
  } catch (error) {
    console.error('Error updating asset:', error);
    res.status(500).json({ error: error.message });
  }
});

// DELETE asset
router.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const [result] = await pool.execute('DELETE FROM assets WHERE id = ?', [id]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Asset not found' });
    }
    res.json({ message: 'Asset deleted successfully' });
  } catch (error) {
    console.error('Error deleting asset:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET assets by category
router.get('/category/:category', async (req, res) => {
  try {
    const { category } = req.params;
    const [rows] = await pool.execute('SELECT * FROM assets WHERE category = ?', [category]);
    res.json({ data: rows });
  } catch (error) {
    console.error('Error fetching assets by category:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET assets by department
router.get('/department/:department', async (req, res) => {
  try {
    const { department } = req.params;
    const [rows] = await pool.execute('SELECT * FROM assets WHERE department = ?', [department]);
    res.json({ data: rows });
  } catch (error) {
    console.error('Error fetching assets by department:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET assets by condition
router.get('/condition/:condition', async (req, res) => {
  try {
    const { condition } = req.params;
    const [rows] = await pool.execute('SELECT * FROM assets WHERE `condition` = ?', [condition]);
    res.json({ data: rows });
  } catch (error) {
    console.error('Error fetching assets by condition:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET assets statistics
router.get('/stats/summary', async (req, res) => {
  try {
    const [totalAssets] = await pool.execute('SELECT COUNT(*) as total FROM assets');
    const [totalValue] = await pool.execute('SELECT SUM(value) as total_value FROM assets');
    const [categoryStats] = await pool.execute('SELECT category, COUNT(*) as count FROM assets GROUP BY category');
    const [departmentStats] = await pool.execute('SELECT department, COUNT(*) as count FROM assets GROUP BY department');
    
    res.json({
      data: {
        total_assets: totalAssets[0].total,
        total_value: totalValue[0].total_value || 0,
        by_category: categoryStats,
        by_department: departmentStats
      }
    });
  } catch (error) {
    console.error('Error fetching asset statistics:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router; 