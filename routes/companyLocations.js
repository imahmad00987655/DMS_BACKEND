import express from 'express';
import pool from '../config/database.js';

const router = express.Router();

// Helper function to generate location code
const generateLocationCode = async (companyId) => {
  try {
    const [rows] = await pool.execute(
      'SELECT COUNT(*) as count FROM company_locations WHERE company_id = ?',
      [companyId]
    );
    const count = rows[0].count + 1;
    return `LOC-${String(count).padStart(3, '0')}`;
  } catch (error) {
    console.error('Error generating location code:', error);
    return `LOC-${Date.now()}`;
  }
};

// GET all locations for a company
router.get('/company/:companyId', async (req, res) => {
  try {
    const { companyId } = req.params;
    const { status, type, search } = req.query;
    
    let sql = `
      SELECT 
        cl.*,
        c.name as company_name,
        u.first_name AS creator_first_name,
        u.last_name AS creator_last_name
      FROM company_locations cl
      LEFT JOIN companies c ON cl.company_id = c.id
      LEFT JOIN users u ON cl.created_by = u.id
      WHERE cl.company_id = ?
    `;
    const params = [companyId];

    if (status) {
      sql += ' AND cl.status = ?';
      params.push(status);
    }

    if (type) {
      sql += ' AND cl.location_type = ?';
      params.push(type);
    }

    if (search) {
      sql += ' AND (cl.location_name LIKE ? OR cl.location_code LIKE ? OR cl.city LIKE ?)';
      const searchPattern = `%${search}%`;
      params.push(searchPattern, searchPattern, searchPattern);
    }

    sql += ' ORDER BY cl.is_primary DESC, cl.created_at DESC';

    const [rows] = await pool.execute(sql, params);
    res.json({ data: rows });
  } catch (error) {
    console.error('Error fetching company locations:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET single location by ID
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await pool.execute(`
      SELECT 
        cl.*,
        c.name as company_name,
        u.first_name AS creator_first_name,
        u.last_name AS creator_last_name,
        u.email AS creator_email
      FROM company_locations cl
      LEFT JOIN companies c ON cl.company_id = c.id
      LEFT JOIN users u ON cl.created_by = u.id
      WHERE cl.id = ?
    `, [id]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Location not found' });
    }
    
    res.json({ data: rows[0] });
  } catch (error) {
    console.error('Error fetching location:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST create new location
router.post('/', async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const {
      company_id,
      location_code,
      location_name,
      location_type,
      address_line1,
      address_line2,
      city,
      state,
      postal_code,
      country,
      is_primary,
      status,
      created_by
    } = req.body;

    // Validate required fields
    if (!company_id || !location_name) {
      await connection.rollback();
      return res.status(400).json({ 
        error: 'Missing required fields',
        required: ['company_id', 'location_name']
      });
    }

    // Generate location code if not provided
    const finalLocationCode = location_code || await generateLocationCode(company_id);

    // If this is set as primary, unset other primary locations for this company
    if (is_primary) {
      await connection.execute(
        'UPDATE company_locations SET is_primary = FALSE WHERE company_id = ?',
        [company_id]
      );
    }

    const sql = `
      INSERT INTO company_locations (
        company_id, location_code, location_name, location_type, address_line1, address_line2,
        city, state, postal_code, country, is_primary, status, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const params = [
      company_id,
      finalLocationCode,
      location_name,
      location_type || 'WAREHOUSE',
      address_line1 || null,
      address_line2 || null,
      city || null,
      state || null,
      postal_code || null,
      country || null,
      is_primary || false,
      status || 'ACTIVE',
      created_by || 1
    ];

    const [result] = await connection.execute(sql, params);

    await connection.commit();

    res.status(201).json({ 
      success: true,
      message: 'Location created successfully',
      data: { 
        id: result.insertId, 
        location_code: finalLocationCode 
      }
    });
  } catch (error) {
    await connection.rollback();
    console.error('Error creating location:', error);
    
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ 
        error: 'Location with this code already exists for this company' 
      });
    }
    
    res.status(500).json({ error: error.message });
  } finally {
    connection.release();
  }
});

// PUT update location
router.put('/:id', async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const { id } = req.params;
    const {
      location_code,
      location_name,
      location_type,
      address_line1,
      address_line2,
      city,
      state,
      postal_code,
      country,
      is_primary,
      status
    } = req.body;

    // Check if location exists
    const [existing] = await connection.execute(
      'SELECT company_id FROM company_locations WHERE id = ?',
      [id]
    );

    if (existing.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Location not found' });
    }

    const companyId = existing[0].company_id;

    // If this is set as primary, unset other primary locations for this company
    if (is_primary) {
      await connection.execute(
        'UPDATE company_locations SET is_primary = FALSE WHERE company_id = ? AND id != ?',
        [companyId, id]
      );
    }

    const sql = `
      UPDATE company_locations SET 
        location_code = ?, location_name = ?, location_type = ?, address_line1 = ?, address_line2 = ?,
        city = ?, state = ?, postal_code = ?, country = ?, is_primary = ?, status = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `;

    const params = [
      location_code,
      location_name,
      location_type || 'WAREHOUSE',
      address_line1 || null,
      address_line2 || null,
      city || null,
      state || null,
      postal_code || null,
      country || null,
      is_primary || false,
      status || 'ACTIVE',
      id
    ];

    const [result] = await connection.execute(sql, params);

    if (result.affectedRows === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Location not found' });
    }

    await connection.commit();

    res.json({ 
      success: true,
      message: 'Location updated successfully' 
    });
  } catch (error) {
    await connection.rollback();
    console.error('Error updating location:', error);
    
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ 
        error: 'Location with this code already exists for this company' 
      });
    }
    
    res.status(500).json({ error: error.message });
  } finally {
    connection.release();
  }
});

// DELETE location
router.delete('/:id', async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const { id } = req.params;
    const { deleted_by } = req.body;

    // Check if location exists
    const [existing] = await connection.execute(
      'SELECT location_name FROM company_locations WHERE id = ?',
      [id]
    );

    if (existing.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Location not found' });
    }

    const locationName = existing[0].location_name;

    // Soft delete by updating status
    const [result] = await connection.execute(
      'UPDATE company_locations SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      ['INACTIVE', id]
    );

    if (result.affectedRows === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Location not found' });
    }

    await connection.commit();

    res.json({ 
      success: true,
      message: `${locationName} has been deleted successfully` 
    });
  } catch (error) {
    await connection.rollback();
    console.error('Error deleting location:', error);
    res.status(500).json({ error: error.message });
  } finally {
    connection.release();
  }
});

// GET location statistics for a company
router.get('/company/:companyId/stats', async (req, res) => {
  try {
    const { companyId } = req.params;
    
    const [rows] = await pool.execute(`
      SELECT 
        COUNT(*) as total_locations,
        SUM(CASE WHEN status = 'ACTIVE' THEN 1 ELSE 0 END) as active_locations,
        SUM(CASE WHEN is_primary = TRUE THEN 1 ELSE 0 END) as primary_locations,
        COUNT(DISTINCT location_type) as location_types,
        COUNT(DISTINCT country) as countries
      FROM company_locations 
      WHERE company_id = ?
    `, [companyId]);
    
    res.json({ data: rows[0] });
  } catch (error) {
    console.error('Error fetching location statistics:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
