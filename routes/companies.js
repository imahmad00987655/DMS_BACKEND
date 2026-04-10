import express from 'express';
import pool from '../config/database.js';

const router = express.Router();

// Helper function to generate company code
const generateCompanyCode = async () => {
  try {
    const [result] = await pool.execute(
      'SELECT company_code FROM companies ORDER BY id DESC LIMIT 1'
    );
    
    if (result.length === 0) {
      return 'COMP001';
    }
    
    const lastCode = result[0].company_code;
    const numPart = parseInt(lastCode.replace('COMP', ''));
    const newNum = numPart + 1;
    return `COMP${String(newNum).padStart(3, '0')}`;
  } catch (error) {
    console.error('Error generating company code:', error);
    return `COMP${Date.now()}`;
  }
};

// GET all companies
router.get('/', async (req, res) => {
  try {
    const { status, country, search } = req.query;
    
    let sql = `
      SELECT 
        c.*,
        u.first_name AS creator_first_name,
        u.last_name AS creator_last_name
      FROM companies c
      LEFT JOIN users u ON c.created_by = u.id
      WHERE 1=1
    `;
    const params = [];

    if (status) {
      sql += ' AND c.status = ?';
      params.push(status);
    }

    if (country) {
      sql += ' AND c.country = ?';
      params.push(country);
    }

    if (search) {
      sql += ' AND (c.name LIKE ? OR c.legal_name LIKE ? OR c.registration_number LIKE ?)';
      const searchPattern = `%${search}%`;
      params.push(searchPattern, searchPattern, searchPattern);
    }

    sql += ' ORDER BY c.created_at DESC';

    const [rows] = await pool.execute(sql, params);
    res.json({ data: rows });
  } catch (error) {
    console.error('Error fetching companies:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET single company by ID
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await pool.execute(`
      SELECT 
        c.*,
        u.first_name AS creator_first_name,
        u.last_name AS creator_last_name,
        u.email AS creator_email
      FROM companies c
      LEFT JOIN users u ON c.created_by = u.id
      WHERE c.id = ?
    `, [id]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Company not found' });
    }
    
    res.json({ data: rows[0] });
  } catch (error) {
    console.error('Error fetching company:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST create new company
router.post('/', async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const {
      name,
      legal_name,
      registration_number,
      strn,
      ntn,
      country,
      currency,
      fiscal_year_start,
      status,
      created_by
    } = req.body;

    // Validate required fields
    if (!name || !legal_name || !registration_number) {
      await connection.rollback();
      return res.status(400).json({ 
        error: 'Missing required fields',
        required: ['name', 'legal_name', 'registration_number']
      });
    }

    // Generate company code
    const company_code = await generateCompanyCode();

    const sql = `
      INSERT INTO companies (
        company_code, name, legal_name, registration_number, strn, ntn, country, currency,
        fiscal_year_start, status, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const params = [
      company_code,
      name,
      legal_name,
      registration_number,
      strn || null,
      ntn || null,
      country || null,
      currency || 'USD',
      fiscal_year_start || null,
      status || 'Active',
      created_by || 1
    ];

    const [result] = await connection.execute(sql, params);

    await connection.commit();

    res.status(201).json({ 
      success: true,
      message: 'Company created successfully',
      data: { 
        id: result.insertId, 
        company_code 
      }
    });
  } catch (error) {
    await connection.rollback();
    console.error('Error creating company:', error);
    
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ 
        error: 'Company with this registration number already exists' 
      });
    }
    
    res.status(500).json({ error: error.message });
  } finally {
    connection.release();
  }
});

// PUT update company
router.put('/:id', async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const { id } = req.params;
    const {
      name,
      legal_name,
      registration_number,
      strn,
      ntn,
      country,
      currency,
      fiscal_year_start,
      status
    } = req.body;

    // Check if company exists
    const [existing] = await connection.execute(
      'SELECT id FROM companies WHERE id = ?',
      [id]
    );

    if (existing.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Company not found' });
    }

    const sql = `
      UPDATE companies SET 
        name = ?, legal_name = ?, registration_number = ?, strn = ?, ntn = ?, country = ?, 
        currency = ?, fiscal_year_start = ?, status = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `;

    const params = [
      name,
      legal_name,
      registration_number,
      strn || null,
      ntn || null,
      country || null,
      currency || 'USD',
      fiscal_year_start || null,
      status || 'Active',
      id
    ];

    const [result] = await connection.execute(sql, params);

    if (result.affectedRows === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Company not found' });
    }

    await connection.commit();

    res.json({ 
      success: true,
      message: 'Company updated successfully' 
    });
  } catch (error) {
    await connection.rollback();
    console.error('Error updating company:', error);
    
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ 
        error: 'Company with this registration number already exists' 
      });
    }
    
    res.status(500).json({ error: error.message });
  } finally {
    connection.release();
  }
});

// DELETE company
router.delete('/:id', async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const { id } = req.params;

    // Check if company exists
    const [companyData] = await connection.execute(
      'SELECT id FROM companies WHERE id = ?',
      [id]
    );

    if (companyData.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Company not found' });
    }

    // Delete company
    const [result] = await connection.execute('DELETE FROM companies WHERE id = ?', [id]);
    
    if (result.affectedRows === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Company not found' });
    }

    await connection.commit();

    res.json({ 
      success: true,
      message: 'Company deleted successfully' 
    });
  } catch (error) {
    await connection.rollback();
    console.error('Error deleting company:', error);
    res.status(500).json({ error: error.message });
  } finally {
    connection.release();
  }
});

// GET companies by status
router.get('/status/:status', async (req, res) => {
  try {
    const { status } = req.params;
    const [rows] = await pool.execute(
      'SELECT * FROM companies WHERE status = ? ORDER BY name',
      [status]
    );
    res.json({ data: rows });
  } catch (error) {
    console.error('Error fetching companies by status:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET companies statistics
router.get('/stats/summary', async (req, res) => {
  try {
    const [totalCompanies] = await pool.execute('SELECT COUNT(*) as total FROM companies');
    const [activeCompanies] = await pool.execute('SELECT COUNT(*) as total FROM companies WHERE status = "Active"');
    const [countryStats] = await pool.execute('SELECT country, COUNT(*) as count FROM companies WHERE country IS NOT NULL GROUP BY country');
    const [currencyStats] = await pool.execute('SELECT currency, COUNT(*) as count FROM companies GROUP BY currency');
    const [statusStats] = await pool.execute('SELECT status, COUNT(*) as count FROM companies GROUP BY status');
    
    res.json({
      data: {
        total_companies: totalCompanies[0].total,
        active_companies: activeCompanies[0].total,
        by_country: countryStats,
        by_currency: currencyStats,
        by_status: statusStats
      }
    });
  } catch (error) {
    console.error('Error fetching company statistics:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
