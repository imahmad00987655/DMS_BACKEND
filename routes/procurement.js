
import express from 'express';
import pool from '../config/database.js';
import { authenticateToken, requireRole } from '../middleware/auth.js';

const router = express.Router();

// OPTIMIZED: Helper function to get next sequence value (uses correct table)
const getNextSequenceValue = async (connection, sequenceName) => {
  // Determine which sequences table to use based on the sequence name
  const tableName = sequenceName.startsWith('AP_') ? 'ap_sequences' : 'ar_sequences';
  
  const [seqResult] = await connection.execute(
    `SELECT current_value FROM ${tableName} WHERE sequence_name = ? FOR UPDATE`,
    [sequenceName]
  );
  
  if (seqResult.length === 0) {
    throw new Error(`Sequence ${sequenceName} not found in ${tableName}`);
  }
  
  const currentValue = seqResult[0].current_value;
  
  // Update sequence for next use (atomic operation)
  await connection.execute(
    `UPDATE ${tableName} SET current_value = current_value + 1 WHERE sequence_name = ?`,
    [sequenceName]
  );
  
  return currentValue;
};

// Helper function to generate document number
const generateDocumentNumber = async (connection, documentType) => {
  const [docResult] = await connection.execute(
    'SELECT prefix, suffix, next_number, number_format FROM po_document_numbers WHERE document_type = ? AND is_active = TRUE',
    [documentType]
  );
  
  if (docResult.length === 0) {
    throw new Error(`Document number configuration not found for ${documentType}`);
  }
  
  const config = docResult[0];
  const formattedNumber = config.next_number.toString().padStart(config.number_format.length, '0');
  const documentNumber = `${config.prefix}${formattedNumber}${config.suffix}`;
  
  // Update next number
  await connection.execute(
    'UPDATE po_document_numbers SET next_number = next_number + 1 WHERE document_type = ?',
    [documentType]
  );
  
  return documentNumber;
};

// Helper function to log audit trail
const logAuditTrail = async (connection, userId, action, documentType, documentId, oldValues = null, newValues = null) => {
  try {
    console.log('🔍 logAuditTrail called with:', { userId, action, documentType, documentId });
    
    // Helper function to safely convert any value to JSON-safe format
    const safeJSONStringify = (value) => {
      try {
        if (value === null || value === undefined) {
          return null;
        }
        
        // If it's a primitive, return as is
        if (typeof value !== 'object') {
          return value;
        }
        
        // If it's an object, clean it recursively
        const cleanObject = (obj) => {
          if (!obj || typeof obj !== 'object') return obj;
          
          if (Array.isArray(obj)) {
            return obj.map(item => cleanObject(item));
          }
          
          const cleaned = {};
          for (const [key, val] of Object.entries(obj)) {
            if (val === undefined) {
              cleaned[key] = null;
            } else if (val === '') {
              cleaned[key] = null;
            } else if (val && typeof val === 'object') {
              cleaned[key] = cleanObject(val);
            } else {
              cleaned[key] = val;
            }
          }
          return cleaned;
        };
        
        const cleaned = cleanObject(value);
        return JSON.stringify(cleaned);
      } catch (error) {
        console.error('🔍 Error in safeJSONStringify:', error);
        return null;
      }
    };

    const oldValuesJSON = safeJSONStringify(oldValues);
    const newValuesJSON = safeJSONStringify(newValues);
    
    console.log('🔍 oldValuesJSON:', oldValuesJSON);
    console.log('🔍 newValuesJSON:', newValuesJSON);

    await connection.execute(`
      INSERT INTO po_audit_log (user_id, action, document_type, document_id, old_values, new_values, created_at)
      VALUES (?, ?, ?, ?, ?, ?, NOW())
    `, [userId, action, documentType, documentId, oldValuesJSON, newValuesJSON]);
    
    console.log('🔍 Audit trail logged successfully');
  } catch (error) {
    console.error('🔍 Error in logAuditTrail:', error);
    // Don't throw error, just log it to avoid breaking the main operation
  }
};

// Use centralized authentication middleware (imported from middleware/auth.js)
// Middleware to check admin role
const requireAdmin = requireRole(['admin']);

// ============================================================================
// PURCHASE AGREEMENTS
// ============================================================================

// OPTIMIZED: Get procurement suppliers endpoint (uses connection pool)
router.get('/suppliers', async (req, res) => {
  try {
    const [suppliers] = await pool.execute(`
      SELECT 
        supplier_id,
        supplier_name,
        supplier_number,
        supplier_type,
        supplier_class,
        supplier_category,
        status
      FROM ap_suppliers 
      WHERE status = 'ACTIVE'
      ORDER BY supplier_name
    `);
    
    res.json(suppliers);
  } catch (error) {
    console.error('Error fetching suppliers:', error);
    res.status(500).json({ error: 'Failed to fetch suppliers' });
  }
});

// OPTIMIZED: Test database connection endpoint (uses connection pool)
router.get('/test-db', async (req, res) => {
  try {
    // Test basic connection
    const [result] = await pool.execute('SELECT 1 as test');
    
    // Test if po_agreements table exists
    const [tables] = await pool.execute("SHOW TABLES LIKE 'po_agreements'");
    
    // Test if ap_suppliers table exists
    const [suppliers] = await pool.execute("SHOW TABLES LIKE 'ap_suppliers'");
    
    res.json({
      success: true,
      message: 'Database connection test successful',
      tables: {
        po_agreements: tables.length > 0,
        ap_suppliers: suppliers.length > 0
      }
    });
  } catch (error) {
    console.error('Database test error:', error);
    res.status(500).json({
      success: false,
      error: 'Database test failed',
      details: error.message
    });
  }
});





// OPTIMIZED: Get agreement lines (uses connection pool)
router.get('/agreements/:agreementId/lines', async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT * FROM po_agreement_lines 
      WHERE agreement_id = ? 
      ORDER BY line_number
    `, [req.params.agreementId]);
    res.json(rows);
  } catch (error) {
    console.error('Error fetching agreement lines:', error);
    res.status(500).json({ error: 'Failed to fetch agreement lines' });
  }
});

// OPTIMIZED: Create agreement line (uses connection pool with transaction)
router.post('/agreements/:agreementId/lines', async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    
    const lineId = await getNextSequenceValue(connection, 'PO_AGREEMENT_LINE_ID_SEQ');
    const {
      line_number, item_code, item_name, description, category, uom,
      quantity, unit_price, line_amount, min_quantity, max_quantity,
      need_by_date, suggested_supplier, suggested_supplier_id, notes
    } = req.body;
    
    await connection.execute(`
      INSERT INTO po_agreement_lines (
        line_id, agreement_id, line_number, item_code, item_name, description,
        category, uom, quantity, unit_price, line_amount, tax_rate, tax_amount,
        gst_rate, gst_amount, min_quantity, max_quantity, need_by_date, 
        suggested_supplier, suggested_supplier_id, notes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      lineId, req.params.agreementId, line_number, item_code, item_name, description,
      category, uom, quantity, unit_price, line_amount, 
      req.body.tax_rate || 0, req.body.tax_amount || 0,
      req.body.gst_rate || 0, req.body.gst_amount || 0,
      min_quantity, max_quantity, need_by_date, suggested_supplier, suggested_supplier_id, notes
    ]);
    
    await connection.commit();
    res.status(201).json({ 
      message: 'Agreement line created successfully',
      line_id: lineId
    });
  } catch (error) {
    await connection.rollback();
    console.error('Error creating agreement line:', error);
    res.status(500).json({ error: 'Failed to create agreement line' });
  } finally {
    connection.release();
  }
});

// ===== REMOVE/COMMENT OUT THE OLD AGREEMENTS ROUTE =====
// OPTIMIZED: Get all purchase agreements (uses connection pool, optimized query)
router.get('/agreements', async (req, res) => {
  try {
    const { search, status, supplier_id } = req.query;
    
    let query = `
      SELECT 
        pa.*,
        sp.supplier_name,
        COALESCE(ps.site_name, 'Default Site') as supplier_site_name,
        u1.first_name as buyer_name,
        u2.first_name as created_by_name
      FROM po_agreements pa
      JOIN ap_suppliers sp ON pa.supplier_id = sp.supplier_id
      LEFT JOIN ap_supplier_sites ps ON pa.supplier_site_id = ps.site_id
      JOIN users u1 ON pa.buyer_id = u1.id
      JOIN users u2 ON pa.created_by = u2.id
      WHERE 1=1
    `;
    
    const params = [];
    
    if (search) {
      query += ` AND (pa.agreement_number LIKE ? OR pa.description LIKE ?)`;
      const searchTerm = `%${search}%`;
      params.push(searchTerm, searchTerm);
    }
    
    if (status && status !== 'ALL') {
      query += ` AND pa.status = ?`;
      params.push(status);
    }
    
    if (supplier_id) {
      query += ` AND pa.supplier_id = ?`;
      params.push(supplier_id);
    }
    
    query += ` ORDER BY pa.created_at DESC`;
    
    const [rows] = await pool.execute(query, params);
    res.json(rows);
  } catch (error) {
    console.error('Error fetching purchase agreements:', error);
    res.status(500).json({ error: 'Failed to fetch purchase agreements' });
  }
});

// Test purchase agreement creation endpoint (no auth)
router.post('/test-agreement', async (req, res) => {
  try {
    console.log('=== TEST AGREEMENT CREATION ===');
    console.log('Request body:', JSON.stringify(req.body, null, 2));
    
    const {
      supplier_id,
      site_id,
      description = '',
      lines = []
    } = req.body;
    
    console.log('Parsed request data:', {
      supplier_id,
      description,
      lines_count: lines?.length || 0
    });
    
    if (!supplier_id) {
      return res.status(400).json({ error: 'supplier_id is required' });
    }
    
    console.log('Creating database connection...');
    const connection = await pool.getConnection();
    console.log('Database connection created successfully');
    
    // Generate agreement ID and number
    const agreementId = Date.now();
    const finalAgreementNumber = `PA${agreementId}`;
    const today = new Date().toISOString().split('T')[0];
    const endDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    
    // Calculate total amount from line items if not provided
    let calculatedTotalAmount = 0;
    if (total_amount && !isNaN(parseFloat(total_amount))) {
      calculatedTotalAmount = parseFloat(total_amount);
    } else if (lines && lines.length > 0) {
      calculatedTotalAmount = lines.reduce((total, line) => {
        return total + (Number(line.line_amount) || 0);
      }, 0);
    }

    console.log('Creating agreement with:', {
      agreementId,
      finalAgreementNumber,
      supplier_id,
      description,
      calculatedTotalAmount
    });
    
    console.log('About to insert agreement header...');
    // Insert agreement header with minimal required fields
    const result = await connection.execute(`
      INSERT INTO po_agreements (
        agreement_id, 
        agreement_number, 
        agreement_type, 
        supplier_id, 
        supplier_site_id,
        buyer_id, 
        agreement_date, 
        effective_start_date, 
        effective_end_date,
        currency_code, 
        exchange_rate, 
        total_amount, 
        amount_used,
        payment_terms_id,
        description, 
        notes, 
        created_by,
        status,
        approval_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      agreementId,           // agreement_id
      finalAgreementNumber,  // agreement_number
      agreement_type,        // agreement_type
      supplier_id,          // supplier_id
      site_id || 1,         // supplier_site_id (use provided site_id or default to 1)
      buyer_id,             // buyer_id
      agreement_date || today,                // agreement_date
      effective_start_date || today,                // effective_start_date
      effective_end_date || endDate,              // effective_end_date
      currency_code || 'USD',                // currency_code
      exchange_rate || 1.0,                  // exchange_rate
      calculatedTotalAmount,                 // total_amount
      0,                    // amount_used (start with 0)
      30,                   // payment_terms_id (default)
      description,          // description
      '',                   // notes
      1,                    // created_by (default)
      status,               // status
      approval_status       // approval_status
    ]);
    
    console.log('Agreement header inserted successfully');
    
    // Create line items if provided
    if (lines && lines.length > 0) {
      console.log('Creating line items:', lines.length);
      
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        console.log(`Processing line ${i + 1}:`, line);
        
        // Use simple timestamp-based line ID
        const lineId = Date.now() + i;
        
        await connection.execute(`
          INSERT INTO po_agreement_lines (
            line_id, agreement_id, line_number, item_code, item_name, description,
            category, uom, quantity, unit_price, line_amount, min_quantity,
            max_quantity, need_by_date, suggested_supplier, suggested_supplier_id, notes
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
          lineId, 
          agreementId, 
          i + 1, 
          line.item_code || '', 
          line.item_name || '',
          line.description || '', 
          line.category || '', 
          line.uom || 'EACH',
          Number(line.quantity) || 1, 
          Number(line.unit_price) || 0, 
          Number(line.line_amount) || 0,
          line.min_quantity ? Number(line.min_quantity) : null, 
          line.max_quantity ? Number(line.max_quantity) : null,
          line.need_by_date || null, 
          line.suggested_supplier || '',
          line.suggested_supplier_id ? Number(line.suggested_supplier_id) : null, 
          line.notes || ''
        ]);
      }
      
      console.log('Line items created successfully');
    }
    
    connection.release();
    
    console.log('Agreement created successfully');
    
    res.status(201).json({
      success: true,
      message: 'Agreement created successfully',
      agreement: {
        agreement_id: agreementId,
        agreement_number: finalAgreementNumber,
        supplier_id,
        description,
        lines_count: lines.length
      }
    });
    
  } catch (error) {
    console.error('Error creating purchase agreement:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({
      success: false,
      error: 'Failed to create agreement',
      details: error.message,
      stack: error.stack
    });
  }
});

// OPTIMIZED: Create purchase agreement (uses connection pool with transaction)
router.post('/agreements', async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    
    const {
      agreement_number,
      agreement_type = '',
      supplier_id,
      site_id,
      buyer_id = 1,
      description = '',
      lines = [],
      status = '',
      approval_status = '',
      currency_code = '',
      exchange_rate = '',
      total_amount = '',
      agreement_date = '',
      effective_start_date = '',
      effective_end_date = ''
    } = req.body;
    
    if (!supplier_id) {
      await connection.rollback();
      connection.release();
      return res.status(400).json({ error: 'supplier_id is required' });
    }
    
    if (!agreement_number) {
      await connection.rollback();
      connection.release();
      return res.status(400).json({ error: 'agreement_number is required' });
    }
    
    // Use the agreement number from frontend, generate ID
    const agreementId = Date.now();
    const finalAgreementNumber = agreement_number;
    const today = new Date().toISOString().split('T')[0];
    const endDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    
    // Calculate total amount from line items if not provided
    let calculatedTotalAmount = 0;
    if (total_amount && !isNaN(parseFloat(total_amount))) {
      calculatedTotalAmount = parseFloat(total_amount);
    } else if (lines && lines.length > 0) {
      calculatedTotalAmount = lines.reduce((total, line) => {
        return total + (Number(line.line_amount) || 0);
      }, 0);
    }

    console.log('Creating agreement with:', {
      agreementId,
      finalAgreementNumber,
      supplier_id,
      description,
      calculatedTotalAmount
    });
    
    console.log('About to insert agreement header...');
    // Get party_id from supplier_id
    const [supplierResult] = await connection.execute(
      'SELECT party_id FROM ap_suppliers WHERE supplier_id = ?',
      [supplier_id]
    );
    
    if (supplierResult.length === 0) {
      await connection.rollback();
      connection.release();
      return res.status(400).json({ error: 'Supplier not found' });
    }
    
    const party_id = supplierResult[0].party_id;
    
    // OPTIMIZED: Batch insert line items instead of loop
    // Insert agreement header with minimal required fields
    await connection.execute(`
      INSERT INTO po_agreements (
        agreement_id, 
        agreement_number, 
        agreement_type, 
        supplier_id, 
        party_id,
        supplier_site_id,
        buyer_id, 
        agreement_date, 
        effective_start_date, 
        effective_end_date,
        currency_code, 
        exchange_rate, 
        total_amount, 
        amount_used,
        payment_terms_id,
        description, 
        notes, 
        created_by,
        status,
        approval_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      agreementId,           // agreement_id
      finalAgreementNumber,  // agreement_number
      agreement_type,        // agreement_type
      supplier_id,          // supplier_id
      party_id,             // party_id
      site_id || 1,         // supplier_site_id (use provided site_id or default to 1)
      buyer_id,             // buyer_id
      agreement_date || today,                // agreement_date
      effective_start_date || today,                // effective_start_date
      effective_end_date || endDate,              // effective_end_date
      currency_code || 'USD',                // currency_code
      exchange_rate || 1.0,                  // exchange_rate
      calculatedTotalAmount,                 // total_amount
      0,                    // amount_used (start with 0)
      30,                   // payment_terms_id (default)
      description,          // description
      '',                   // notes
      1,                    // created_by (default)
      status,               // status
      approval_status       // approval_status
    ]);
    
    console.log('Agreement header inserted successfully');
    
    // Create line items if provided
    if (lines && lines.length > 0) {
      console.log('Creating line items:', lines.length);
      
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        console.log(`Processing line ${i + 1}:`, line);
        
        // Use simple timestamp-based line ID
        const lineId = Date.now() + i;
        
        await connection.execute(`
          INSERT INTO po_agreement_lines (
            line_id, agreement_id, line_number, item_code, item_name, description,
            category, uom, quantity, unit_price, line_amount, min_quantity,
            max_quantity, need_by_date, suggested_supplier, suggested_supplier_id, notes
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
          lineId, 
          agreementId, 
          i + 1, 
          line.item_code || '', 
          line.item_name || '',
          line.description || '', 
          line.category || '', 
          line.uom || 'EACH',
          Number(line.quantity) || 1, 
          Number(line.unit_price) || 0, 
          Number(line.line_amount) || 0,
          line.min_quantity ? Number(line.min_quantity) : null, 
          line.max_quantity ? Number(line.max_quantity) : null,
          line.need_by_date || null, 
          line.suggested_supplier || '',
          line.suggested_supplier_id ? Number(line.suggested_supplier_id) : null, 
          line.notes || ''
        ]);
      }
      
      console.log('Line items created successfully');
    }
    
    connection.release();
    
    console.log('Agreement created successfully');
    
    res.status(201).json({
      success: true,
      message: 'Agreement created successfully',
      agreement: {
        agreement_id: agreementId,
        agreement_number: finalAgreementNumber,
        supplier_id,
        description,
        lines_count: lines.length
      }
    });
    
  } catch (error) {
    console.error('Error creating purchase agreement:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({
      success: false,
      error: 'Failed to create agreement',
      details: error.message,
      stack: error.stack
    });
  }
});

// OPTIMIZED: Get purchase agreement by ID (uses connection pool, removed unnecessary JOIN)
router.get('/agreements/:id', async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT 
        pa.*,
        sp.supplier_name,
        COALESCE(ps.site_name, 'Default Site') as supplier_site_name,
        u1.first_name as buyer_name,
        u2.first_name as created_by_name
      FROM po_agreements pa
      JOIN ap_suppliers sp ON pa.supplier_id = sp.supplier_id
      LEFT JOIN ap_supplier_sites ps ON pa.supplier_site_id = ps.site_id
      JOIN users u1 ON pa.buyer_id = u1.id
      JOIN users u2 ON pa.created_by = u2.id
      WHERE pa.agreement_id = ?
    `, [req.params.id]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Purchase agreement not found' });
    }
    
    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching purchase agreement:', error);
    res.status(500).json({ error: 'Failed to fetch purchase agreement' });
  }
});

// Create purchase agreement (using simple method)
router.post('/create-agreement', async (req, res) => {
  try {
    console.log('=== AGREEMENT CREATION VIA /agreements ===');
    console.log('Request body:', JSON.stringify(req.body, null, 2));
    
    // Get basic data from request
    const { supplier_id, site_id, description = 'New Agreement', lines = [] } = req.body;
    
    if (!supplier_id) {
      return res.status(400).json({ error: 'supplier_id is required' });
    }
    
    const connection = await pool.getConnection();
    
    // Generate unique ID using timestamp
    const agreementId = Date.now();
    const agreementNumber = `PA${agreementId}`;
    const today = new Date().toISOString().split('T')[0];
    const endDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    
    console.log('Creating agreement with:', {
      agreementId,
      agreementNumber,
      supplier_id,
      description
    });
    
    // Insert with all required fields
    const result = await connection.execute(`
      INSERT INTO po_agreements (
        agreement_id, 
        agreement_number, 
        agreement_type, 
        supplier_id, 
        supplier_site_id,
        buyer_id, 
        agreement_date, 
        effective_start_date, 
        effective_end_date,
        currency_code, 
        exchange_rate, 
        total_amount, 
        payment_terms_id,
        description, 
        notes, 
        created_by,
        status,
        approval_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      agreementId,           // agreement_id
      agreementNumber,       // agreement_number
      'BLANKET',            // agreement_type
      supplier_id,          // supplier_id
      site_id || 1,         // supplier_site_id (use provided site_id or default to 1)
      1,                    // buyer_id
      today,                // agreement_date
      today,                // effective_start_date
      endDate,              // effective_end_date
      'USD',                // currency_code
      1.0,                  // exchange_rate
      0.00,                 // total_amount
      30,                   // payment_terms_id
      description,          // description
      '',                   // notes
      1,                    // created_by
      'ACTIVE',             // status
      'PENDING'             // approval_status
    ]);
    
    // Create line items if provided
    if (lines && lines.length > 0) {
      console.log('Creating line items:', lines.length);
      
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineId = await getNextSequenceValue(connection, 'PO_AGREEMENT_LINE_ID_SEQ');
        
        await connection.execute(`
          INSERT INTO po_agreement_lines (
            line_id, agreement_id, line_number, item_code, item_name, description,
            category, uom, quantity, unit_price, line_amount, tax_rate, tax_amount,
            gst_rate, gst_amount, min_quantity, max_quantity, need_by_date, 
            suggested_supplier, suggested_supplier_id, notes
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
          lineId, agreementId, i + 1, line.item_code || '', line.item_name || '',
          line.description || '', line.category || '', line.uom || 'EACH',
          line.quantity || 1, line.unit_price || 0, line.line_amount || 0,
          line.tax_rate || 0, line.tax_amount || 0, line.gst_rate || 0, line.gst_amount || 0,
          line.min_quantity || null, line.max_quantity || null,
          line.need_by_date || null, line.suggested_supplier || '',
          line.suggested_supplier_id || null, line.notes || ''
        ]);
      }
      
      console.log('Line items created successfully');
    }
    
    connection.release();
    
    console.log('Agreement created successfully');
    
    res.status(201).json({
      success: true,
      message: 'Agreement created successfully',
      agreement: {
        agreement_id: agreementId,
        agreement_number: agreementNumber,
        supplier_id,
        description,
        lines_count: lines.length
      }
    });
    
  } catch (error) {
    console.error('Error creating agreement:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create agreement',
      details: error.message
    });
  }
});

// Update purchase agreement
router.put('/agreements/:id', authenticateToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    
    // Get current values for audit trail
    const [currentResult] = await connection.execute(
      'SELECT * FROM po_agreements WHERE agreement_id = ?',
      [req.params.id]
    );
    
    if (currentResult.length === 0) {
      connection.release();
      return res.status(404).json({ error: 'Purchase agreement not found' });
    }
    
    const oldValues = currentResult[0];
    
    const {
      agreement_type, supplier_id, site_id, buyer_id,
      agreement_date, effective_start_date, effective_end_date,
      currency_code, exchange_rate, total_amount, payment_terms_id,
      description, notes, status, approval_status
    } = req.body;

    // Map site_id to supplier_site_id for database compatibility
    const supplier_site_id = site_id;
    
    // Handle approval status changes
    let approvedBy = null;
    let approvedAt = null;
    
    if (approval_status === 'APPROVED') {
      approvedBy = req.user.id;
      approvedAt = new Date();
    } else if (approval_status === 'REJECTED' || approval_status === 'PENDING') {
      // Reset approval info when status changes away from approved
      approvedBy = null;
      approvedAt = null;
    }
    
    // Convert undefined values to null for MySQL
    const params = [
      agreement_type || null,
      supplier_id || null,
      supplier_site_id || null,
      buyer_id || null,
      agreement_date || null,
      effective_start_date || null,
      effective_end_date || null,
      currency_code || null,
      exchange_rate || null,
      total_amount || null,
      payment_terms_id || null,
      description || null,
      notes || null,
      status || null,
      approval_status || null,
      approvedBy,
      approvedAt,
      req.params.id
    ];
    
    await connection.execute(`
      UPDATE po_agreements SET
        agreement_type = ?, supplier_id = ?, supplier_site_id = ?, buyer_id = ?,
        agreement_date = ?, effective_start_date = ?, effective_end_date = ?,
        currency_code = ?, exchange_rate = ?, total_amount = ?, payment_terms_id = ?,
        description = ?, notes = ?, status = ?, approval_status = ?, 
        approved_by = ?, approved_at = ?, updated_at = NOW()
      WHERE agreement_id = ?
    `, params);
    
    // Log audit trail
    console.log('🔍 About to log audit trail with cleaned values');
    console.log('🔍 req.body before cleaning:', req.body);
    
    // Clean the request body to remove any undefined values
    const cleanRequestBody = (obj) => {
      if (!obj || typeof obj !== 'object') return obj;
      const cleaned = {};
      for (const [key, value] of Object.entries(obj)) {
        if (value === undefined) {
          cleaned[key] = null;
        } else if (value === '') {
          cleaned[key] = null;
        } else if (value && typeof value === 'object') {
          cleaned[key] = cleanRequestBody(value);
        } else {
          cleaned[key] = value;
        }
      }
      return cleaned;
    };
    
    const cleanedNewValues = req.body ? cleanRequestBody(req.body) : null;
    console.log('🔍 cleanedNewValues:', cleanedNewValues);
    
    await logAuditTrail(connection, req.user.id, 'UPDATE', 'AGREEMENT', req.params.id, oldValues, cleanedNewValues);
    
    connection.release();
    res.json({ message: 'Purchase agreement updated successfully' });
  } catch (error) {
    console.error('Error updating purchase agreement:', error);
    res.status(500).json({ error: 'Failed to update purchase agreement' });
  }
});

// Delete purchase agreement (soft delete)
router.delete('/agreements/:id', requireAdmin, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    
    // Get current values for audit trail
    const [currentResult] = await connection.execute(
      'SELECT * FROM po_agreements WHERE agreement_id = ?',
      [req.params.id]
    );
    
    if (currentResult.length === 0) {
      connection.release();
      return res.status(404).json({ error: 'Purchase agreement not found' });
    }
    
    const oldValues = currentResult[0];
    
    // Soft delete by setting status to CANCELLED
    await connection.execute(
      'UPDATE po_agreements SET status = "CANCELLED", updated_at = NOW() WHERE agreement_id = ?',
      [req.params.id]
    );
    
    // Log audit trail
    await logAuditTrail(connection, req.user.id, 'DELETE', 'AGREEMENT', req.params.id, oldValues, { status: 'CANCELLED' });
    
    connection.release();
    res.json({ message: 'Purchase agreement cancelled successfully' });
  } catch (error) {
    console.error('Error cancelling purchase agreement:', error);
    res.status(500).json({ error: 'Failed to cancel purchase agreement' });
  }
});

// ============================================================================
// PURCHASE REQUISITIONS
// ============================================================================

// OPTIMIZED: Get all purchase requisitions (uses connection pool)
router.get('/requisitions', async (req, res) => {
  try {
    const { search, status, requester_id } = req.query;
    
    let query = `
      SELECT 
        pr.*,
        u1.first_name as requester_name,
        u2.first_name as buyer_name,
        u3.first_name as created_by_name
      FROM po_requisitions pr
      JOIN users u1 ON pr.requester_id = u1.id
      LEFT JOIN users u2 ON pr.buyer_id = u2.id
      JOIN users u3 ON pr.created_by = u3.id
      WHERE 1=1
    `;
    
    const params = [];
    
    if (search) {
      query += ` AND (pr.requisition_number LIKE ? OR pr.description LIKE ?)`;
      const searchTerm = `%${search}%`;
      params.push(searchTerm, searchTerm);
    }
    
    if (status && status !== 'ALL') {
      query += ` AND pr.status = ?`;
      params.push(status);
    }
    
    if (requester_id) {
      query += ` AND pr.requester_id = ?`;
      params.push(requester_id);
    }
    
    query += ` ORDER BY pr.created_at DESC`;
    
    const [rows] = await pool.execute(query, params);
    res.json(rows);
  } catch (error) {
    console.error('Error fetching purchase requisitions:', error);
    res.status(500).json({ error: 'Failed to fetch purchase requisitions' });
  }
});

// OPTIMIZED: Get purchase requisition by ID with lines (uses connection pool, parallel queries)
router.get('/requisitions/:id', async (req, res) => {
  try {
    // OPTIMIZED: Fetch header and lines in parallel
    const [headerRows, lineRows] = await Promise.all([
      pool.execute(`
        SELECT 
          pr.*,
          u1.first_name as requester_name,
          u2.first_name as buyer_name,
          u3.first_name as created_by_name
        FROM po_requisitions pr
        JOIN users u1 ON pr.requester_id = u1.id
        LEFT JOIN users u2 ON pr.buyer_id = u2.id
        JOIN users u3 ON pr.created_by = u3.id
        WHERE pr.requisition_id = ?
      `, [req.params.id]),
      pool.execute(`
        SELECT * FROM po_requisition_lines 
        WHERE requisition_id = ? 
        ORDER BY line_number
      `, [req.params.id])
    ]);
    
    if (headerRows[0].length === 0) {
      return res.status(404).json({ error: 'Purchase requisition not found' });
    }
    
    const result = {
      ...headerRows[0][0],
      lines: lineRows[0]
    };
    
    res.json(result);
  } catch (error) {
    console.error('Error fetching purchase requisition:', error);
    res.status(500).json({ error: 'Failed to fetch purchase requisition' });
  }
});

// Create purchase requisition
router.post('/requisitions', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    
    // Get next requisition ID and generate requisition number
    const requisitionId = await getNextSequenceValue(connection, 'PO_REQUISITION_ID_SEQ');
    const requisitionNumber = await generateDocumentNumber(connection, 'REQUISITION');
    
    const {
      requester_id, buyer_id, department_id, need_by_date, urgency,
      currency_code, exchange_rate, description, justification, notes, lines
    } = req.body;
    
    // Calculate total amount from lines
    const totalAmount = lines.reduce((sum, line) => sum + (line.line_amount || 0), 0);
    
    await connection.execute(`
      INSERT INTO po_requisitions (
        requisition_id, requisition_number, requester_id, buyer_id, department_id,
        need_by_date, urgency, currency_code, exchange_rate, total_amount,
        description, justification, notes, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [requisitionId, requisitionNumber, requester_id, buyer_id, department_id,
        need_by_date, urgency, currency_code, exchange_rate, totalAmount,
        description, justification, notes, req.user.id]);
    
    // Insert lines
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineId = await getNextSequenceValue(connection, 'PO_LINE_ID_SEQ');
      
      await connection.execute(`
        INSERT INTO po_requisition_lines (
          line_id, requisition_id, line_number, item_code, item_name,
          description, category, uom, quantity, unit_price, line_amount,
          need_by_date, suggested_supplier, suggested_supplier_id, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [lineId, requisitionId, i + 1, line.item_code, line.item_name,
          line.description, line.category, line.uom, line.quantity, line.unit_price, line.line_amount,
          line.need_by_date, line.suggested_supplier, line.suggested_supplier_id, line.notes]);
    }
    
    // Log audit trail
    await logAuditTrail(connection, req.user.id, 'CREATE', 'REQUISITION', requisitionId, null, req.body);
    
    connection.release();
    res.status(201).json({ 
      message: 'Purchase requisition created successfully',
      requisition_id: requisitionId,
      requisition_number: requisitionNumber
    });
  } catch (error) {
    console.error('Error creating purchase requisition:', error);
    res.status(500).json({ error: 'Failed to create purchase requisition' });
  }
});

// OPTIMIZED: Update purchase requisition (uses connection pool, batch insert lines)
router.put('/requisitions/:id', async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    
    // Get current values for audit trail
    const [currentResult] = await connection.execute(
      'SELECT * FROM po_requisitions WHERE requisition_id = ?',
      [req.params.id]
    );
    
    if (currentResult.length === 0) {
      await connection.rollback();
      connection.release();
      return res.status(404).json({ error: 'Purchase requisition not found' });
    }
    
    const oldValues = currentResult[0];
    
    const {
      requester_id, buyer_id, department_id, need_by_date, urgency,
      currency_code, exchange_rate, description, justification, notes, lines, status
    } = req.body;
    
    // Calculate total amount from lines
    const totalAmount = lines.reduce((sum, line) => sum + (line.line_amount || 0), 0);
    
    await connection.execute(`
      UPDATE po_requisitions SET
        requester_id = ?, buyer_id = ?, department_id = ?, need_by_date = ?, urgency = ?,
        currency_code = ?, exchange_rate = ?, total_amount = ?, description = ?,
        justification = ?, notes = ?, status = ?, updated_at = NOW()
      WHERE requisition_id = ?
    `, [requester_id, buyer_id, department_id, need_by_date, urgency,
        currency_code, exchange_rate, totalAmount, description,
        justification, notes, status, req.params.id]);

    // Delete existing lines and insert new ones
    await connection.execute('DELETE FROM po_requisition_lines WHERE requisition_id = ?', [req.params.id]);
    
    // OPTIMIZED: Batch insert updated lines
    if (lines && lines.length > 0) {
      const lineValues = [];
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineId = await getNextSequenceValue(connection, 'PO_LINE_ID_SEQ');
        
        lineValues.push([
          lineId, req.params.id, i + 1, line.item_code, line.item_name,
          line.description, line.category, line.uom, line.quantity, line.unit_price, line.line_amount,
          line.need_by_date, line.suggested_supplier, line.suggested_supplier_id, line.notes
        ]);
      }
      
      const placeholders = lineValues.map(() => '(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').join(', ');
      const flatValues = lineValues.flat();
      
      await connection.execute(`
        INSERT INTO po_requisition_lines (
          line_id, requisition_id, line_number, item_code, item_name,
          description, category, uom, quantity, unit_price, line_amount,
          need_by_date, suggested_supplier, suggested_supplier_id, notes
        ) VALUES ${placeholders}
      `, flatValues);
    }
    
    // Log audit trail
    await logAuditTrail(connection, req.user?.id || 1, 'UPDATE', 'REQUISITION', req.params.id, oldValues, req.body);
    
    await connection.commit();
    connection.release();
    res.json({ message: 'Purchase requisition updated successfully' });
  } catch (error) {
    await connection.rollback();
    connection.release();
    console.error('Error updating purchase requisition:', error);
    res.status(500).json({ error: 'Failed to update purchase requisition' });
  }
});

// Delete purchase requisition (soft delete)
router.delete('/requisitions/:id', requireAdmin, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    
    // Get current values for audit trail
    const [currentResult] = await connection.execute(
      'SELECT * FROM po_requisitions WHERE requisition_id = ?',
      [req.params.id]
    );
    
    if (currentResult.length === 0) {
      connection.release();
      return res.status(404).json({ error: 'Purchase requisition not found' });
    }
    
    const oldValues = currentResult[0];
    
    // Soft delete by setting status to CANCELLED
    await connection.execute(
      'UPDATE po_requisitions SET status = "CANCELLED", updated_at = NOW() WHERE requisition_id = ?',
      [req.params.id]
    );
    
    // Log audit trail
    await logAuditTrail(connection, req.user.id, 'DELETE', 'REQUISITION', req.params.id, oldValues, { status: 'CANCELLED' });
    
    connection.release();
    res.json({ message: 'Purchase requisition cancelled successfully' });
  } catch (error) {
    console.error('Error cancelling purchase requisition:', error);
    res.status(500).json({ error: 'Failed to cancel purchase requisition' });
  }
});

// ============================================================================
// PURCHASE ORDERS
// ============================================================================

// Helper: Update PO header status based on all related receipts
/**
 * Update inventory item boxes and packets based on accepted quantity in GRN
 * @param {object} connection - MySQL connection
 * @param {number} receiptId - The GRN receipt ID
 * @param {boolean} isReversal - If true, reduce inventory (for deletions/cancellations)
 */
const updateInventoryFromGRN = async (connection, receiptId, isReversal = false) => {
  try {
    // Get all GRN lines with item_code, accepted quantity, and PO line info for packet_quantity
    const [receiptLines] = await connection.execute(
      `SELECT 
        prl.receipt_line_id, 
        prl.item_code, 
        prl.quantity_accepted,
        pl.packet_quantity as po_packet_quantity
       FROM po_receipt_lines prl
       LEFT JOIN po_lines pl ON prl.line_id = pl.line_id
       WHERE prl.receipt_id = ? 
         AND prl.item_code IS NOT NULL 
         AND prl.item_code != '' 
         AND prl.quantity_accepted > 0`,
      [receiptId]
    );

    // OPTIMIZED: Batch fetch all inventory details in one query
    if (receiptLines.length === 0) return;
    
    const itemCodes = receiptLines.map(line => line.item_code).filter(Boolean);
    if (itemCodes.length === 0) return;
    
    const [allInventoryDetails] = await connection.execute(
      `SELECT iid.id, iid.inventory_item_id, iid.box_quantity, iid.packet_quantity, iid.version, ih.item_code
       FROM inventory_item_details iid
       JOIN inventory_items ih ON iid.inventory_item_id = ih.id
       WHERE ih.item_code IN (${itemCodes.map(() => '?').join(',')}) AND iid.is_active = 1`,
      itemCodes
    );
    
    // Create map for quick lookup
    const inventoryMap = {};
    allInventoryDetails.forEach(detail => {
      if (!inventoryMap[detail.item_code]) {
        inventoryMap[detail.item_code] = detail;
      }
    });
    
    // Prepare batch updates
    const updates = [];
    const packetUpdates = [];
    
    for (const line of receiptLines) {
      const itemCode = line.item_code;
      const acceptedQty = parseFloat(line.quantity_accepted) || 0;
      
      if (acceptedQty <= 0 || !inventoryMap[itemCode]) {
        if (!inventoryMap[itemCode]) {
          console.warn(`Inventory item not found for item_code: ${itemCode}`);
        }
        continue;
      }

      const detail = inventoryMap[itemCode];
      let currentBoxQty = parseFloat(detail.box_quantity) || 0;
      let packetsPerBox = parseFloat(detail.packet_quantity) || 0;

      // packet_quantity represents "packets per box" (constant for the item)
      // If packet_quantity is 0, try to use PO line packet_quantity, otherwise default to 1
      if (packetsPerBox <= 0) {
        const poPacketQty = parseFloat(line.po_packet_quantity) || 0;
        if (poPacketQty > 0) {
          packetsPerBox = poPacketQty;
          packetUpdates.push({ id: detail.id, itemCode, packetsPerBox, source: 'PO' });
        } else {
          packetsPerBox = 1;
          packetUpdates.push({ id: detail.id, itemCode, packetsPerBox, source: 'default' });
        }
      }

      // Calculate total units: boxes × packets per box
      const totalUnits = currentBoxQty * packetsPerBox;

      let newTotalUnits;
      if (isReversal) {
        // Reduce inventory (for deletions/cancellations)
        newTotalUnits = Math.max(0, totalUnits - acceptedQty);
      } else {
        // Add inventory (for receipts)
        newTotalUnits = totalUnits + acceptedQty;
      }

      // Calculate new boxes (packets per box remains constant)
      const newBoxQty = newTotalUnits / packetsPerBox;
      const newBoxQtyRounded = Math.round(newBoxQty * 100) / 100;

      updates.push({
        id: detail.id,
        boxQty: newBoxQtyRounded,
        itemCode,
        currentBoxQty,
        packetsPerBox,
        totalUnits,
        newTotalUnits,
        acceptedQty
      });
    }
    
    // Batch update packet_quantity for items that need it
    if (packetUpdates.length > 0) {
      await connection.execute(`
        UPDATE inventory_item_details 
        SET packet_quantity = CASE id
          ${packetUpdates.map(() => 'WHEN ? THEN ?').join(' ')}
        END,
        updated_at = CURRENT_TIMESTAMP
        WHERE id IN (${packetUpdates.map(() => '?').join(',')})
      `, [
        ...packetUpdates.flatMap(u => [u.id, u.packetsPerBox]),
        ...packetUpdates.map(u => u.id)
      ]);
      
      packetUpdates.forEach(u => {
        console.log(`Set packets_per_box for ${u.itemCode} ${u.source === 'PO' ? 'from PO' : 'default'}: ${u.packetsPerBox}`);
      });
    }
    
    // Batch update box_quantity for all items
    if (updates.length > 0) {
      await connection.execute(`
        UPDATE inventory_item_details 
        SET box_quantity = CASE id
          ${updates.map(() => 'WHEN ? THEN ?').join(' ')}
        END,
        updated_at = CURRENT_TIMESTAMP
        WHERE id IN (${updates.map(() => '?').join(',')})
      `, [
        ...updates.flatMap(u => [u.id, u.boxQty]),
        ...updates.map(u => u.id)
      ]);
      
      updates.forEach(u => {
        const calculatedTotal = u.boxQty * u.packetsPerBox;
        console.log(`Updated inventory for ${u.itemCode}: ${u.currentBoxQty} boxes × ${u.packetsPerBox} packets/box (${u.totalUnits} units) → ${u.boxQty} boxes × ${u.packetsPerBox} packets/box (${calculatedTotal.toFixed(2)} calculated units, ${u.newTotalUnits} actual units) (${isReversal ? '-' : '+'}${u.acceptedQty} units)`);
      });
    }
  } catch (error) {
    console.error('Error updating inventory from GRN:', error);
    throw error;
  }
};

const updatePOStatusFromReceipts = async (connection, headerId) => {
  try {
    const [rows] = await connection.execute(
      `
        SELECT 
          SUM(pl.quantity) AS total_quantity,
          SUM(COALESCE(prl.quantity_accepted, 0)) AS total_accepted,
          SUM(COALESCE(prl.quantity_received, 0)) AS total_received
        FROM po_lines pl
        LEFT JOIN po_receipt_lines prl ON prl.line_id = pl.line_id
        WHERE pl.header_id = ?
      `,
      [headerId]
    );

    if (!rows || rows.length === 0) {
      return;
    }

    const stats = rows[0];
    const totalQty = Number(stats.total_quantity) || 0;
    const totalAccepted = Number(stats.total_accepted) || 0;
    const totalReceived = Number(stats.total_received) || 0;

    if (totalQty <= 0) {
      return;
    }

    let newStatus = null;

    // If all ordered quantity has been accepted (across all GRNs), close the PO
    if (totalAccepted >= totalQty) {
      newStatus = 'CLOSED';
    } else if (totalReceived > 0) {
      // Otherwise, if at least some quantity has been received (accepted and/or rejected), mark as RECEIVED
      newStatus = 'RECEIVED';
    }

    if (!newStatus) {
      return;
    }

    // Don't override cancelled orders
    await connection.execute(
      `
        UPDATE po_headers
        SET status = ?, updated_at = NOW()
        WHERE header_id = ? AND status <> 'CANCELLED'
      `,
      [newStatus, headerId]
    );
  } catch (error) {
    console.error('Error updating PO status from receipts:', error);
    // Swallow error so it doesn't block main GRN operation
  }
};

// OPTIMIZED: Get all purchase orders (uses connection pool)
router.get('/purchase-orders', async (req, res) => {
  try {
    const { search, status, supplier_id } = req.query;
    
    let query = `
      SELECT 
        ph.*,
        s.supplier_name,
        ss.site_name as supplier_site_name,
        u1.first_name as buyer_name,
        u2.first_name as created_by_name,
        pr.requisition_number,
        pa.agreement_number
      FROM po_headers ph
      JOIN ap_suppliers s ON ph.supplier_id = s.supplier_id
      LEFT JOIN ap_supplier_sites ss ON ph.supplier_site_id = ss.site_id
      JOIN users u1 ON ph.buyer_id = u1.id
      JOIN users u2 ON ph.created_by = u2.id
      LEFT JOIN po_requisitions pr ON ph.requisition_id = pr.requisition_id
      LEFT JOIN po_agreements pa ON ph.agreement_id = pa.agreement_id
      WHERE 1=1
    `;
    
    const params = [];
    
    if (search) {
      query += ` AND (ph.po_number LIKE ? OR ph.description LIKE ?)`;
      const searchTerm = `%${search}%`;
      params.push(searchTerm, searchTerm);
    }
    
    if (status && status !== 'ALL') {
      query += ` AND ph.status = ?`;
      params.push(status);
    }
    
    if (supplier_id) {
      query += ` AND ph.supplier_id = ?`;
      params.push(supplier_id);
    }
    
    query += ` ORDER BY ph.created_at DESC`;
    
    const [rows] = await pool.execute(query, params);
    res.json(rows);
  } catch (error) {
    console.error('Error fetching purchase orders:', error);
    res.status(500).json({ error: 'Failed to fetch purchase orders' });
  }
});

// OPTIMIZED: Get purchase order by ID with lines (uses connection pool, parallel queries)
router.get('/purchase-orders/:id', async (req, res) => {
  try {
    // OPTIMIZED: Fetch header and lines in parallel for faster response
    const [headerRows, lineRows] = await Promise.all([
      pool.execute(`
        SELECT 
          ph.*,
          s.supplier_name,
          ss.site_name as supplier_site_name,
          u1.first_name as buyer_name,
          u2.first_name as created_by_name,
          pr.requisition_number,
          pa.agreement_number
        FROM po_headers ph
        JOIN ap_suppliers s ON ph.supplier_id = s.supplier_id
        LEFT JOIN ap_supplier_sites ss ON ph.supplier_site_id = ss.site_id
        JOIN users u1 ON ph.buyer_id = u1.id
        JOIN users u2 ON ph.created_by = u2.id
        LEFT JOIN po_requisitions pr ON ph.requisition_id = pr.requisition_id
        LEFT JOIN po_agreements pa ON ph.agreement_id = pa.agreement_id
        WHERE ph.header_id = ?
      `, [req.params.id]),
      pool.execute(`
        SELECT * FROM po_lines 
        WHERE header_id = ? 
        ORDER BY line_number
      `, [req.params.id])
    ]);
    
    if (headerRows[0].length === 0) {
      return res.status(404).json({ error: 'Purchase order not found' });
    }
    
    const result = {
      ...headerRows[0][0],
      lines: lineRows[0]
    };
    
    res.json(result);
  } catch (error) {
    console.error('Error fetching purchase order:', error);
    res.status(500).json({ error: 'Failed to fetch purchase order' });
  }
});

// OPTIMIZED: Create purchase order (uses connection pool)
router.post('/purchase-orders', authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    
    const {
      po_number, po_type, supplier_id, supplier_site_id, buyer_id, requisition_id, agreement_id,
      po_date, order_date, need_by_date, currency_code, exchange_rate, payment_terms_id,
      description, notes, lines
    } = req.body;
    
    // Use po_date if order_date is not provided
    const effectiveDate = po_date || order_date;
    
    // Sanitize all parameters to prevent undefined values
    // For exchange_rate, use provided value if it's a valid number, otherwise default to 1.0
    const sanitizedParams = {
      po_type: po_type || 'STANDARD',
      supplier_id: supplier_id || 0,
      supplier_site_id: supplier_site_id || supplier_id || 0,
      buyer_id: buyer_id || 0,
      requisition_id: requisition_id === undefined || requisition_id === '' ? null : requisition_id,
      agreement_id: agreement_id === undefined || agreement_id === '' ? null : agreement_id,
      po_date: effectiveDate || new Date().toISOString().split('T')[0],
      need_by_date: need_by_date || effectiveDate || new Date().toISOString().split('T')[0],
      currency_code: currency_code || 'USD',
      exchange_rate: (exchange_rate !== undefined && exchange_rate !== null && exchange_rate !== '') 
        ? parseFloat(exchange_rate) || 1.0 
        : 1.0,
      payment_terms_id: payment_terms_id || 30,
      description: description || '',
      notes: notes || ''
    };
    
    // Additional validation to ensure no undefined values
    Object.keys(sanitizedParams).forEach(key => {
      if (sanitizedParams[key] === undefined) {
        console.error(`Parameter ${key} is still undefined after sanitization`);
        sanitizedParams[key] = null;
      }
    });
    
    // Get next PO ID and generate PO number (simplified)
    console.log('About to query sequence PO_HEADER_ID_SEQ');
    const [seqResult] = await connection.execute(
      'SELECT current_value FROM ar_sequences WHERE sequence_name = ?',
      ['PO_HEADER_ID_SEQ']
    );
    console.log('Sequence query result:', seqResult);
    console.log('Sequence result length:', seqResult.length);
    if (seqResult.length === 0) {
      throw new Error('Sequence PO_HEADER_ID_SEQ not found');
    }
    const headerId = seqResult[0].current_value;
    console.log('Current sequence value:', headerId);
    
    // Increment sequence first to avoid conflicts
    await connection.execute(
      'UPDATE ar_sequences SET current_value = current_value + 1 WHERE sequence_name = ?',
      ['PO_HEADER_ID_SEQ']
    );
    console.log('Sequence incremented, using headerId:', headerId);
    
    // Use frontend-provided PO number if available, otherwise generate one
    let poNumber;
    if (po_number && po_number.trim() !== '') {
      // Use the PO number provided by the frontend
      poNumber = po_number.trim();
      console.log('Using frontend-provided PO number:', poNumber);
    } else {
      // Generate PO number from database sequence
      const [docResult] = await connection.execute(
        'SELECT prefix, suffix, next_number, number_format FROM po_document_numbers WHERE document_type = ? AND is_active = TRUE LIMIT 1',
        ['PURCHASE_ORDER']
      );
      if (docResult.length === 0) {
        throw new Error('Document number configuration not found for PURCHASE_ORDER');
      }
      const config = docResult[0];
      const formattedNumber = config.next_number.toString().padStart(config.number_format.length, '0');
      poNumber = `${config.prefix}${formattedNumber}${config.suffix}`;
      console.log('Generated PO number from database:', poNumber);
    }
    
    // Validate that lines are provided
    if (!lines || lines.length === 0) {
      throw new Error('At least one line item is required');
    }
    
    // Calculate totals from lines with proper decimal handling
    const subtotal = Math.round((lines.reduce((sum, line) => sum + (parseFloat(line.line_amount) || 0), 0)) * 100) / 100;
    const taxAmount = Math.round((lines.reduce((sum, line) => sum + (parseFloat(line.tax_amount) || 0), 0)) * 100) / 100;
    const gstAmount = Math.round((lines.reduce((sum, line) => sum + (parseFloat(line.gst_amount) || 0), 0)) * 100) / 100;
    const totalAmount = Math.round((subtotal + taxAmount + gstAmount) * 100) / 100;
    
    console.log('Create PO - Calculated amounts:', { subtotal, taxAmount, totalAmount });
    
    // Log sanitized parameters for debugging
    console.log('Sanitized parameters for header insert:', sanitizedParams);
    console.log('User info:', req.user);
    console.log('User ID:', req.user?.id);
    
    // Ensure user ID is valid (check both id and userId for compatibility)
    if (!req.user || (!req.user.id && !req.user.userId)) {
      throw new Error('User not authenticated or user ID missing');
    }
    
    // Use either id or userId
    const userId = req.user.id || req.user.userId;
    console.log('Using user ID:', userId);
    
    // Create the final insert values array
    const insertValues = [
      headerId, 
      poNumber, 
      sanitizedParams.po_type, 
      sanitizedParams.supplier_id, 
      sanitizedParams.supplier_site_id, 
      sanitizedParams.buyer_id,
      sanitizedParams.requisition_id, 
      sanitizedParams.agreement_id, 
      sanitizedParams.po_date, 
      sanitizedParams.need_by_date, 
      sanitizedParams.currency_code,
      sanitizedParams.exchange_rate, 
      subtotal, 
      taxAmount, 
      totalAmount, 
      sanitizedParams.payment_terms_id,
      sanitizedParams.description, 
      sanitizedParams.notes, 
      userId
    ];
    
    console.log('Header insert values:', insertValues);
    console.log('Checking for undefined values in insert array...');
    insertValues.forEach((value, index) => {
      if (value === undefined) {
        console.error(`Value at index ${index} is undefined:`, value);
      }
    });
    
    // Insert header
    try {
      console.log('Attempting to insert header with values:', insertValues);
      await connection.execute(`
        INSERT INTO po_headers (
          header_id, po_number, po_type, supplier_id, supplier_site_id, buyer_id,
          requisition_id, agreement_id, po_date, need_by_date, currency_code,
          exchange_rate, subtotal, tax_amount, total_amount, payment_terms_id,
          description, notes, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, insertValues);
      console.log('✅ Header inserted successfully');
    } catch (insertError) {
      console.error('❌ Error inserting header:', insertError);
      console.error('Insert values that caused error:', insertValues);
      throw insertError;
    }
    
    // Update document number sequence only when generating new numbers
    if (!po_number || po_number.trim() === '') {
      await connection.execute(
        'UPDATE po_document_numbers SET next_number = next_number + 1 WHERE document_type = ?',
        ['PURCHASE_ORDER']
      );
      console.log('Updated document number sequence');
    } else {
      console.log('Skipping document number sequence update (using frontend PO number)');
    }
    
    // Insert lines
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Get next line ID and increment sequence atomically
      const [lineSeqResult] = await connection.execute(
        'SELECT current_value FROM ar_sequences WHERE sequence_name = ? FOR UPDATE',
        ['PO_LINE_ID_SEQ']
      );
      const lineId = lineSeqResult[0].current_value;
      
      // Increment line sequence immediately after reading
      await connection.execute(
        'UPDATE ar_sequences SET current_value = current_value + 1 WHERE sequence_name = ?',
        ['PO_LINE_ID_SEQ']
      );
      
      // Sanitize line parameters with proper number formatting
      const sanitizedLine = {
        item_code: line.item_code || '',
        item_name: line.item_name || '',
        description: line.description || '',
        category: line.category || '',
        uom: line.uom || 'PCS',
        quantity: Math.round((parseFloat(line.quantity) || 0) * 100) / 100,
        box_quantity: Math.round((parseFloat(line.box_quantity) || 0) * 100) / 100,
        packet_quantity: Math.round((parseFloat(line.packet_quantity) || 0) * 100) / 100,
        unit_price: Math.round((parseFloat(line.unit_price) || 0) * 100) / 100,
        line_amount: Math.round((parseFloat(line.line_amount) || 0) * 100) / 100,
        tax_rate: Math.round((parseFloat(line.tax_rate) || 0) * 100) / 100,
        tax_amount: Math.round((parseFloat(line.tax_amount) || 0) * 100) / 100,
        promised_date: line.promised_date || null,
        notes: line.notes || ''
      };
      
      console.log(`Line ${i + 1} sanitized parameters:`, sanitizedLine);
      
      // Create line insert values array
      const lineInsertValues = [
        lineId, 
        headerId, 
        i + 1, 
        sanitizedLine.item_code, 
        sanitizedLine.item_name, 
        sanitizedLine.description,
        sanitizedLine.category, 
        sanitizedLine.uom, 
        sanitizedLine.quantity,
        sanitizedLine.box_quantity,
        sanitizedLine.packet_quantity,
        sanitizedLine.unit_price, 
        sanitizedLine.line_amount,
        sanitizedLine.tax_rate, 
        sanitizedLine.tax_amount, 
        sanitizedLine.promised_date, 
        sanitizedLine.notes
      ];
      
      console.log(`Line ${i + 1} insert values:`, lineInsertValues);
      console.log(`Checking for undefined values in line ${i + 1} insert array...`);
      lineInsertValues.forEach((value, index) => {
        if (value === undefined) {
          console.error(`Line ${i + 1} value at index ${index} is undefined:`, value);
        }
      });
      
      await connection.execute(`
        INSERT INTO po_lines (
          line_id, header_id, line_number, item_code, item_name, description,
          category, uom, quantity, box_quantity, packet_quantity, unit_price, line_amount, 
          tax_rate, tax_amount, promised_date, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, lineInsertValues);
    }
    
    // Commit transaction
    await connection.commit();
    
    res.status(201).json({ 
      message: 'Purchase order created successfully',
      header_id: headerId,
      po_number: poNumber
    });
  } catch (error) {
    console.error('Error creating purchase order:', error);
    console.error('Error stack:', error.stack);
    console.error('Request body:', req.body);
    
    // Rollback transaction on error
    if (connection && connection.rollback) {
      try {
        await connection.rollback();
      } catch (rollbackError) {
        console.error('Error rolling back transaction:', rollbackError);
      }
    }
    
    // Check if it's a database constraint error
    if (error.code === 'ER_NO_REFERENCED_ROW_2') {
      return res.status(400).json({ 
        error: 'Referenced record not found. Please check supplier, supplier site, or buyer information.' 
      });
    }
    
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ 
        error: 'Duplicate entry. This PO number may already exist.' 
      });
    }
    
    res.status(500).json({ error: 'Failed to create purchase order', details: error.message });
  } finally {
    // Release connection back to pool
    if (connection) {
      connection.release();
    }
  }
});

// OPTIMIZED: Update purchase order (uses connection pool)
router.put('/purchase-orders/:id', authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    
    // Get current values for audit trail
    const [currentResult] = await connection.execute(
      'SELECT * FROM po_headers WHERE header_id = ?',
      [req.params.id]
    );
    
    if (currentResult.length === 0) {
      await connection.rollback();
      connection.release();
      return res.status(404).json({ error: 'Purchase order not found' });
    }
    
    const oldValues = currentResult[0];
    
    const {
      po_type, supplier_id, supplier_site_id, buyer_id, requisition_id, agreement_id,
      po_date, need_by_date, currency_code, exchange_rate: exchangeRateRaw, payment_terms_id,
      description, notes, lines, status, approval_status
    } = req.body;
    
    // Parse exchange_rate if provided (handle both string and number)
    const exchange_rate = exchangeRateRaw !== undefined && exchangeRateRaw !== null && exchangeRateRaw !== ''
      ? (typeof exchangeRateRaw === 'string' ? parseFloat(exchangeRateRaw) : exchangeRateRaw)
      : undefined;
    
    // Validate required fields
    if (!lines || !Array.isArray(lines) || lines.length === 0) {
      await connection.rollback();
      connection.release();
      return res.status(400).json({ error: 'At least one line item is required' });
    }
    
    // Calculate totals from lines with proper decimal handling
    const subtotal = Math.round((lines.reduce((sum, line) => sum + (parseFloat(line.line_amount) || 0), 0)) * 100) / 100;
    const taxAmount = Math.round((lines.reduce((sum, line) => sum + (parseFloat(line.tax_amount) || 0), 0)) * 100) / 100;
    const totalAmount = Math.round((subtotal + taxAmount) * 100) / 100;
    
    console.log('Calculated amounts:', { subtotal, taxAmount, totalAmount });
    console.log('Amount types:', { 
      subtotalType: typeof subtotal, 
      taxAmountType: typeof taxAmount, 
      gstAmountType: typeof gstAmount, 
      totalAmountType: typeof totalAmount 
    });
    console.log('Raw line data:', lines.map(line => ({
      line_amount: line.line_amount,
      tax_amount: line.tax_amount,
      line_amount_type: typeof line.line_amount,
      tax_amount_type: typeof line.tax_amount
    })));
    
    // Validate that amounts don't exceed DECIMAL(15,2) limit (999,999,999,999,999.99)
    const maxAmount = 999999999999999.99;
    if (Math.abs(subtotal) > maxAmount || Math.abs(taxAmount) > maxAmount || 
        Math.abs(totalAmount) > maxAmount) {
      await connection.rollback();
      connection.release();
      return res.status(400).json({ error: 'Amount values exceed maximum allowed limit' });
    }
    
    // Convert undefined values to null for MySQL, but preserve existing values for required fields
    // For exchange_rate, use provided value if it's not undefined, otherwise use old value
    const params = [
      po_type || oldValues.po_type,
      supplier_id || oldValues.supplier_id,
      supplier_site_id || oldValues.supplier_site_id,
      buyer_id || oldValues.buyer_id,
      requisition_id || null,
      agreement_id || null,
      po_date || oldValues.po_date, // Use existing po_date if not provided
      need_by_date || oldValues.need_by_date, // Use existing need_by_date if not provided
      currency_code || oldValues.currency_code,
      exchange_rate !== undefined ? exchange_rate : oldValues.exchange_rate,
      subtotal || oldValues.subtotal,
      taxAmount || oldValues.tax_amount,
      totalAmount || oldValues.total_amount,
      payment_terms_id || oldValues.payment_terms_id,
      description || null,
      notes || null,
      status || oldValues.status,
      approval_status || oldValues.approval_status,
      req.params.id
    ];
    
    console.log('SQL UPDATE parameters:', params);
    console.log('Parameter types:', params.map((param, index) => ({ index, value: param, type: typeof param })));
    
    // Test the total_amount value specifically
    console.log('Testing total_amount value:', {
      value: totalAmount,
      type: typeof totalAmount,
      isFinite: Number.isFinite(totalAmount),
      isNaN: Number.isNaN(totalAmount),
      stringValue: String(totalAmount),
      length: String(totalAmount).length
    });
    
    console.log('🔄 Updating PO header with params:', params.length, 'parameters');
    try {
      await connection.execute(`
        UPDATE po_headers SET
          po_type = ?, supplier_id = ?, supplier_site_id = ?, buyer_id = ?,
          requisition_id = ?, agreement_id = ?, po_date = ?, need_by_date = ?,
          currency_code = ?, exchange_rate = ?, subtotal = ?, tax_amount = ?,
          total_amount = ?, payment_terms_id = ?, description = ?, notes = ?,
          status = ?, approval_status = ?, updated_at = NOW()
        WHERE header_id = ?
      `, params);
      console.log('✅ PO header updated successfully');
    } catch (updateError) {
      console.error('❌ Error updating PO header:', updateError);
      throw updateError;
    }

    // Delete existing lines and insert new ones
    console.log('🔄 Deleting existing lines for PO:', req.params.id);
    try {
      await connection.execute('DELETE FROM po_lines WHERE header_id = ?', [req.params.id]);
      console.log('✅ Existing lines deleted successfully');
    } catch (deleteError) {
      console.error('❌ Error deleting existing lines:', deleteError);
      throw deleteError;
    }
    
    // OPTIMIZED: Batch insert updated lines instead of loop
    if (lines && lines.length > 0) {
      console.log(`🔄 Processing ${lines.length} line items for insertion`);
      const lineValues = [];
      try {
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          console.log(`🔄 Processing line ${i + 1}/${lines.length}:`, { item_code: line.item_code, item_name: line.item_name });
          
          let lineId;
          try {
            console.log(`🔄 Getting sequence for line ${i + 1}`);
            lineId = await getNextSequenceValue(connection, 'PO_LINE_ID_SEQ');
            console.log(`✅ Got sequence value: ${lineId} for line ${i + 1}`);
          } catch (seqError) {
            console.error(`❌ Error getting sequence for line ${i + 1}:`, seqError);
            console.error(`❌ Sequence error details:`, {
              name: seqError.name,
              message: seqError.message,
              code: seqError.code,
              stack: seqError.stack
            });
            throw new Error(`Failed to get sequence for line ${i + 1}: ${seqError.message}`);
          }
          
          const lineData = [
            lineId,
            req.params.id,
            i + 1,
            line.item_code || null,
            line.item_name || null,
            line.description || null,
            line.category || null,
            line.uom || 'PCS',
            Math.round((parseFloat(line.quantity) || 0) * 100) / 100,
            Math.round((parseFloat(line.box_quantity) || 0) * 100) / 100,
            Math.round((parseFloat(line.packet_quantity) || 0) * 100) / 100,
            Math.round((parseFloat(line.unit_price) || 0) * 100) / 100,
            Math.round((parseFloat(line.line_amount) || 0) * 100) / 100,
            Math.round((parseFloat(line.tax_rate) || 0) * 100) / 100,
            Math.round((parseFloat(line.tax_amount) || 0) * 100) / 100,
            line.promised_date || null,
            line.notes || null
          ];
          
          console.log(`✅ Line ${i + 1} data prepared:`, { lineId, header_id: req.params.id, line_number: i + 1 });
          lineValues.push(lineData);
        }
        
        if (lineValues.length === 0) {
          throw new Error('No line values prepared for insertion');
        }
        
        const placeholders = lineValues.map(() => '(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').join(', ');
        const flatValues = lineValues.flat();
        
        console.log(`🔄 Inserting ${lineValues.length} lines with ${flatValues.length} total values`);
        console.log(`🔄 Placeholders count: ${placeholders.split('?').length - 1}, Values count: ${flatValues.length}`);
        
        if (flatValues.length !== (lineValues.length * 17)) {
          throw new Error(`Value count mismatch: Expected ${lineValues.length * 17}, got ${flatValues.length}`);
        }
        
        try {
          await connection.execute(`
            INSERT INTO po_lines (
              line_id, header_id, line_number, item_code, item_name, description,
              category, uom, quantity, box_quantity, packet_quantity, unit_price, line_amount, 
              tax_rate, tax_amount, promised_date, notes
            ) VALUES ${placeholders}
          `, flatValues);
          
          console.log('✅ Lines inserted successfully');
        } catch (insertError) {
          console.error('❌ Error executing INSERT statement:', insertError);
          console.error('❌ INSERT error details:', {
            name: insertError.name,
            message: insertError.message,
            code: insertError.code,
            errno: insertError.errno,
            sqlState: insertError.sqlState,
            sqlMessage: insertError.sqlMessage
          });
          throw insertError;
        }
      } catch (lineError) {
        console.error('❌ Error in line insertion process:', lineError);
        throw lineError; // Re-throw to be caught by outer catch
      }
    } else {
      console.log('⚠️ No lines provided for insertion');
    }
    
    // Log audit trail (don't fail if audit logging fails)
    try {
      console.log('🔄 Logging audit trail');
      await logAuditTrail(connection, req.user?.id || req.user?.userId || 1, 'UPDATE', 'PURCHASE_ORDER', req.params.id, oldValues, req.body);
      console.log('✅ Audit trail logged successfully');
    } catch (auditError) {
      console.error('⚠️ Error logging audit trail (non-fatal):', auditError);
      // Don't throw - audit logging failure shouldn't break the update
    }
    
    // Commit transaction
    console.log('🔄 Committing transaction');
    try {
      await connection.commit();
      console.log('✅ Transaction committed successfully');
    } catch (commitError) {
      console.error('❌ Error committing transaction:', commitError);
      throw commitError;
    }
    
    connection.release();
    console.log('✅ Purchase order updated successfully, connection released');
    
    res.json({ message: 'Purchase order updated successfully' });
  } catch (error) {
    console.error('❌ Error updating purchase order:', error);
    console.error('❌ Error name:', error.name);
    console.error('❌ Error message:', error.message);
    console.error('❌ Error code:', error.code);
    console.error('❌ Error stack:', error.stack);
    console.error('❌ Request body:', JSON.stringify(req.body, null, 2));
    console.error('❌ PO ID:', req.params.id);
    
    // Rollback transaction on error
    if (connection) {
      try {
        await connection.rollback();
        console.log('✅ Transaction rolled back successfully');
      } catch (rollbackError) {
        console.error('❌ Error rolling back transaction:', rollbackError);
      }
    }
    
    // Provide more specific error messages
    let errorMessage = error.message || 'Failed to update purchase order';
    let statusCode = 500;
    
    if (error.code === 'ER_NO_REFERENCED_ROW_2') {
      errorMessage = 'Referenced record not found. Please check supplier, supplier site, or buyer information.';
      statusCode = 400;
    } else if (error.code === 'ER_DUP_ENTRY') {
      errorMessage = 'Duplicate entry detected. Please check your data.';
      statusCode = 400;
    } else if (error.message && error.message.includes('Sequence')) {
      errorMessage = `Sequence error: ${error.message}`;
      statusCode = 500;
    }
    
    res.status(statusCode).json({ 
      error: 'Failed to update purchase order',
      message: errorMessage,
      details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      code: error.code
    });
  } finally {
    // Release connection back to pool
    if (connection) {
      connection.release();
    }
  }
});

// OPTIMIZED: Update purchase order status / approval status only (uses connection pool)
router.patch('/purchase-orders/:id/status', authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const { id } = req.params;
    const { status, approval_status } = req.body;
    
    if ((status === undefined || status === null || status === '') &&
        (approval_status === undefined || approval_status === null || approval_status === '')) {
      connection.release();
      return res.status(400).json({ error: 'No status fields provided' });
    }
    
    const [existing] = await connection.execute(
      'SELECT header_id, status, approval_status, approved_by, approved_at FROM po_headers WHERE header_id = ?',
      [id]
    );
    
    if (existing.length === 0) {
      connection.release();
      return res.status(404).json({ error: 'Purchase order not found' });
    }
    
    const validStatuses = ['DRAFT', 'APPROVED', 'RELEASED', 'RECEIVED', 'CLOSED', 'CANCELLED'];
    const validApprovalStatuses = ['PENDING', 'APPROVED', 'REJECTED'];
    
    const updateFields = [];
    const params = [];
    
    if (status !== undefined && status !== null && status !== '') {
      const normalizedStatus = String(status).toUpperCase().trim();
      if (!validStatuses.includes(normalizedStatus)) {
        connection.release();
        return res.status(400).json({ 
          error: `Invalid status value '${status}'. Must be one of: ${validStatuses.join(', ')}` 
        });
      }
      updateFields.push('status = ?');
      params.push(normalizedStatus);
    }
    
    if (approval_status !== undefined && approval_status !== null && approval_status !== '') {
      const normalizedApproval = String(approval_status).toUpperCase().trim();
      if (!validApprovalStatuses.includes(normalizedApproval)) {
        connection.release();
        return res.status(400).json({ 
          error: `Invalid approval_status value '${approval_status}'. Must be one of: ${validApprovalStatuses.join(', ')}` 
        });
      }
      updateFields.push('approval_status = ?');
      params.push(normalizedApproval);
      
      // Track approver when approved, reset otherwise
      if (normalizedApproval === 'APPROVED') {
        updateFields.push('approved_by = ?');
        updateFields.push('approved_at = NOW()');
        params.push(req.user?.id || null);
      } else {
        updateFields.push('approved_by = NULL');
        updateFields.push('approved_at = NULL');
      }
    }
    
    updateFields.push('updated_at = NOW()');
    params.push(id);
    
    const updateQuery = `UPDATE po_headers SET ${updateFields.join(', ')} WHERE header_id = ?`;
    await connection.execute(updateQuery, params);
    
    await logAuditTrail(connection, req.user?.id || 1, 'UPDATE', 'PURCHASE_ORDER_STATUS', id, existing[0], req.body);
    
    connection.release();
    res.json({ message: 'Purchase order status updated successfully' });
  } catch (error) {
    console.error('Error updating purchase order status:', error);
    if (connection) {
      try {
        connection.release();
      } catch (closeError) {
        console.error('Error closing connection after status update:', closeError);
      }
    }
    res.status(500).json({ error: 'Failed to update purchase order status' });
  }
});

// Delete purchase order (soft delete)
router.delete('/purchase-orders/:id', requireAdmin, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    
    // Get current values for audit trail
    const [currentResult] = await connection.execute(
      'SELECT * FROM po_headers WHERE header_id = ?',
      [req.params.id]
    );
    
    if (currentResult.length === 0) {
      connection.release();
      return res.status(404).json({ error: 'Purchase order not found' });
    }
    
    const oldValues = currentResult[0];
    
    // Soft delete by setting status to CANCELLED
    await connection.execute(
      'UPDATE po_headers SET status = "CANCELLED", updated_at = NOW() WHERE header_id = ?',
      [req.params.id]
    );
    
    // Log audit trail
    await logAuditTrail(connection, req.user?.id || req.user?.userId || 1, 'DELETE', 'PURCHASE_ORDER', req.params.id, oldValues, { status: 'CANCELLED' });
    
    connection.release();
    res.json({ message: 'Purchase order cancelled successfully' });
  } catch (error) {
    console.error('Error cancelling purchase order:', error);
    if (connection) {
      connection.release();
    }
    res.status(500).json({ error: 'Failed to cancel purchase order' });
  }
});

// ============================================================================
// GOODS RECEIPT NOTES
// ============================================================================

// OPTIMIZED: Get all goods receipts (uses pool directly, no connection management)
router.get('/receipts', async (req, res) => {
  try {
    const { search, status, header_id } = req.query;
    
    let query = `
      SELECT 
        pr.*,
        ph.po_number,
        ph.supplier_id,
        ph.supplier_site_id,
        s.supplier_name,
        u.first_name as created_by_name
      FROM po_receipts pr
      JOIN po_headers ph ON pr.header_id = ph.header_id
      JOIN ap_suppliers s ON ph.supplier_id = s.supplier_id
      JOIN users u ON pr.created_by = u.id
      WHERE 1=1
    `;
    
    const params = [];
    
    if (search) {
      query += ` AND (pr.receipt_number LIKE ? OR pr.notes LIKE ?)`;
      const searchTerm = `%${search}%`;
      params.push(searchTerm, searchTerm);
    }
    
    if (status && status !== 'ALL') {
      query += ` AND pr.status = ?`;
      params.push(status);
    }
    
    if (header_id) {
      query += ` AND pr.header_id = ?`;
      params.push(header_id);
    }
    
    query += ` ORDER BY pr.created_at DESC`;
    
    const [rows] = await pool.execute(query, params);
    res.json(rows);
  } catch (error) {
    console.error('Error fetching goods receipts:', error);
    res.status(500).json({ error: 'Failed to fetch goods receipts' });
  }
});

// OPTIMIZED: Get goods receipt by ID with lines (uses pool directly, parallel queries)
router.get('/receipts/:id', async (req, res) => {
  try {
    // OPTIMIZED: Fetch header and lines in parallel
    const [headerRows, lineRows] = await Promise.all([
      pool.execute(`
        SELECT 
          pr.*,
          ph.po_number,
          ph.supplier_id,
          ph.supplier_site_id,
          s.supplier_name,
          u.first_name as created_by_name
        FROM po_receipts pr
        JOIN po_headers ph ON pr.header_id = ph.header_id
        JOIN ap_suppliers s ON ph.supplier_id = s.supplier_id
        JOIN users u ON pr.created_by = u.id
        WHERE pr.receipt_id = ?
      `, [req.params.id]),
      pool.execute(`
        SELECT 
          prl.*,
          pl.item_name as po_item_name,
          pl.quantity as po_quantity,
          pl.unit_price as po_unit_price,
          pl.tax_rate as po_tax_rate,
          pl.tax_amount as po_tax_amount
        FROM po_receipt_lines prl
        JOIN po_lines pl ON prl.line_id = pl.line_id
        WHERE prl.receipt_id = ? 
        ORDER BY prl.line_number
      `, [req.params.id])
    ]);
    
    if (headerRows[0].length === 0) {
      return res.status(404).json({ error: 'Goods receipt not found' });
    }
    
    const result = {
      ...headerRows[0][0],
      lines: lineRows[0]
    };
    
    res.json(result);
  } catch (error) {
    console.error('Error fetching goods receipt:', error);
    res.status(500).json({ error: 'Failed to fetch goods receipt' });
  }
});

// OPTIMIZED: Create goods receipt (uses connection pool)
router.post('/receipts', authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    
    // Get next receipt ID and generate receipt number
    const receiptId = await getNextSequenceValue(connection, 'PO_RECEIPT_ID_SEQ');
    const receiptNumber = await generateDocumentNumber(connection, 'RECEIPT');
    
    const {
      header_id, receipt_date, receipt_type, currency_code, exchange_rate, notes, status, lines
    } = req.body;
    
    // Calculate subtotal and tax from lines; default tax to 0 if not provided
    const subtotal = lines.reduce((sum, line) => sum + (Number(line.line_amount) || 0), 0);
    const taxAmount = lines.reduce((sum, line) => sum + (Number(line.tax_amount) || 0), 0);
    const totalAmount = subtotal + taxAmount;
    
    // Convert undefined values to null for MySQL
    const receiptParams = [
      receiptId,
      receiptNumber,
      header_id || null,
      receipt_date || null,
      receipt_type || 'STANDARD',
      currency_code || 'USD',
      exchange_rate || 1.0,
      totalAmount || 0,
      status || 'DRAFT',
      notes || null,
      req.user?.id || 1 // Fallback to user ID 1 if req.user is undefined
    ];
    
    
    await connection.execute(`
      INSERT INTO po_receipts (
        receipt_id, receipt_number, header_id, receipt_date, receipt_type,
        currency_code, exchange_rate, total_amount, status, notes, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, receiptParams);
    
    // OPTIMIZED: Batch insert lines and batch update PO lines
    if (lines && lines.length > 0) {
      const lineValues = [];
      const poLineUpdates = [];
      
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const receiptLineId = await getNextSequenceValue(connection, 'PO_RECEIPT_LINE_ID_SEQ');
        
        lineValues.push([
          receiptLineId,
          receiptId,
          line.line_id || null,
          i + 1,
          line.item_code || null,
          line.item_name || null,
          line.description || null,
          line.uom || 'EA',
          line.quantity_ordered || 0,
          line.quantity_received || 0,
          line.quantity_accepted || 0,
          line.quantity_rejected || 0,
          line.unit_price || 0,
          line.tax_rate || 0,
          line.tax_amount || 0,
          line.line_amount || 0,
          line.lot_number || null,
          line.serial_number || null,
          line.expiration_date || null,
          line.rejection_reason || null,
          line.notes || null
        ]);
        
        if (line.line_id && line.quantity_received) {
          poLineUpdates.push({ line_id: line.line_id, quantity: line.quantity_received });
        }
      }
      
      // Batch insert all receipt lines
      const placeholders = lineValues.map(() => '(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').join(', ');
      const flatValues = lineValues.flat();
      
      await connection.execute(`
        INSERT INTO po_receipt_lines (
          receipt_line_id, receipt_id, line_id, line_number, item_code, item_name,
          description, uom, quantity_ordered, quantity_received, quantity_accepted,
          quantity_rejected, unit_price, tax_rate, tax_amount, line_amount, lot_number, serial_number,
          expiration_date, rejection_reason, notes
        ) VALUES ${placeholders}
      `, flatValues);
      
      // Batch update PO line received quantities
      if (poLineUpdates.length > 0) {
        const updatePlaceholders = poLineUpdates.map(() => 'WHEN ? THEN quantity_received + ?').join(' ');
        const updateIds = poLineUpdates.map(u => u.line_id);
        const updateValues = poLineUpdates.flatMap(u => [u.line_id, u.quantity]);
        
        await connection.execute(`
          UPDATE po_lines SET 
            quantity_received = CASE line_id
              ${updatePlaceholders}
            END,
            updated_at = NOW()
          WHERE line_id IN (${updateIds.map(() => '?').join(',')})
        `, [...updateValues, ...updateIds]);
      }
    }
    
    // Update PO header received amount (include tax so it matches PO total)
    await connection.execute(`
      UPDATE po_headers SET 
        amount_received = amount_received + ?,
        updated_at = NOW()
      WHERE header_id = ?
    `, [totalAmount, header_id]);
    
    // Recalculate PO header status (RECEIVED vs CLOSED) based on all related receipts
    await updatePOStatusFromReceipts(connection, header_id);
    
    // Update inventory based on accepted quantities (always update when goods are received)
    try {
      await updateInventoryFromGRN(connection, receiptId, false);
    } catch (inventoryError) {
      console.error('Failed to update inventory from GRN:', inventoryError);
      // Don't fail the request if inventory update fails, but log it
    }
    
    // Log audit trail
    await logAuditTrail(connection, req.user.id, 'CREATE', 'RECEIPT', receiptId, null, req.body);
    
    // Commit the transaction
    await connection.commit();
    connection.release();
    res.status(201).json({ 
      message: 'Goods receipt created successfully',
      receipt_id: receiptId,
      receipt_number: receiptNumber
    });
  } catch (error) {
    if (connection) {
      await connection.rollback();
      connection.release();
    }
    console.error('Error creating goods receipt:', error);
    res.status(500).json({ 
      error: 'Failed to create goods receipt',
      details: error.message 
    });
  }
});

// OPTIMIZED: Update goods receipt (uses connection pool with transaction)
router.put('/receipts/:id', authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    
    // Get current values for audit trail
    const [currentResult] = await connection.execute(
      'SELECT * FROM po_receipts WHERE receipt_id = ?',
      [req.params.id]
    );
    
    if (currentResult.length === 0) {
      await connection.rollback();
      connection.release();
      return res.status(404).json({ error: 'Goods receipt not found' });
    }
    
    const oldValues = currentResult[0];
    
    const {
      receipt_date, receipt_type, currency_code, exchange_rate, notes, lines, status
    } = req.body;
    
    // Calculate subtotal and tax from lines
    const subtotal = lines.reduce((sum, line) => sum + (Number(line.line_amount) || 0), 0);
    const taxAmount = lines.reduce((sum, line) => sum + (Number(line.tax_amount) || 0), 0);
    const totalAmount = subtotal + taxAmount;
    
    await connection.execute(`
      UPDATE po_receipts SET
        receipt_date = ?, receipt_type = ?, currency_code = ?, exchange_rate = ?,
        total_amount = ?, notes = ?, status = ?, updated_at = NOW()
      WHERE receipt_id = ?
    `, [receipt_date, receipt_type, currency_code, exchange_rate,
        totalAmount, notes, status, req.params.id]);

    // Get old lines before deleting to reverse inventory
    const [oldLines] = await connection.execute(
      `SELECT item_code, quantity_accepted 
       FROM po_receipt_lines 
       WHERE receipt_id = ? AND item_code IS NOT NULL AND item_code != '' AND quantity_accepted > 0`,
      [req.params.id]
    );
    
    // OPTIMIZED: Batch reverse old inventory (reduce inventory by old accepted quantities)
    if (oldLines.length > 0) {
      const oldItemCodes = oldLines.map(line => line.item_code).filter(Boolean);
      
      if (oldItemCodes.length > 0) {
        // Batch fetch all inventory details
        const [oldInventoryDetails] = await connection.execute(
          `SELECT iid.id, iid.box_quantity, iid.packet_quantity, ih.item_code
           FROM inventory_item_details iid
           JOIN inventory_items ih ON iid.inventory_item_id = ih.id
           WHERE ih.item_code IN (${oldItemCodes.map(() => '?').join(',')}) AND iid.is_active = 1`,
          oldItemCodes
        );
        
        // Create map for quick lookup
        const oldInventoryMap = {};
        oldInventoryDetails.forEach(detail => {
          if (!oldInventoryMap[detail.item_code]) {
            oldInventoryMap[detail.item_code] = detail;
          }
        });
        
        // Prepare batch updates
        const reverseUpdates = [];
        
        for (const oldLine of oldLines) {
          const itemCode = oldLine.item_code;
          const oldAcceptedQty = parseFloat(oldLine.quantity_accepted) || 0;
          
          if (oldAcceptedQty <= 0 || !oldInventoryMap[itemCode]) continue;

          const detail = oldInventoryMap[itemCode];
          const currentBoxQty = parseFloat(detail.box_quantity) || 0;
          const currentPacketQty = parseFloat(detail.packet_quantity) || 0;
          const totalUnits = currentBoxQty * currentPacketQty;

          if (currentPacketQty > 0) {
            const newTotalUnits = Math.max(0, totalUnits - oldAcceptedQty);
            const newBoxQty = Math.floor(newTotalUnits / currentPacketQty);
            const newPacketQty = newTotalUnits % currentPacketQty;

            reverseUpdates.push({
              id: detail.id,
              boxQty: newBoxQty,
              packetQty: newPacketQty
            });
          }
        }
        
        // Batch update all reversed inventory
        if (reverseUpdates.length > 0) {
          await connection.execute(`
            UPDATE inventory_item_details 
            SET box_quantity = CASE id
              ${reverseUpdates.map(() => 'WHEN ? THEN ?').join(' ')}
            END,
            packet_quantity = CASE id
              ${reverseUpdates.map(() => 'WHEN ? THEN ?').join(' ')}
            END,
            updated_at = CURRENT_TIMESTAMP
            WHERE id IN (${reverseUpdates.map(() => '?').join(',')})
          `, [
            ...reverseUpdates.flatMap(u => [u.id, u.boxQty]),
            ...reverseUpdates.flatMap(u => [u.id, u.packetQty]),
            ...reverseUpdates.map(u => u.id)
          ]);
        }
      }
    }

    // Delete existing lines and insert new ones
    await connection.execute('DELETE FROM po_receipt_lines WHERE receipt_id = ?', [req.params.id]);
    
    // OPTIMIZED: Batch insert updated lines instead of individual inserts
    if (lines.length > 0) {
      // Get all sequence values at once (if needed, otherwise generate IDs)
      const receiptLineValues = [];
      
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const receiptLineId = await getNextSequenceValue(connection, 'PO_RECEIPT_LINE_ID_SEQ');
        
        receiptLineValues.push([
          receiptLineId,
          req.params.id,
          line.line_id,
          i + 1,
          line.item_code,
          line.item_name,
          line.description,
          line.uom,
          line.quantity_ordered,
          line.quantity_received,
          line.quantity_accepted,
          line.quantity_rejected,
          line.unit_price,
          line.tax_rate || 0,
          line.tax_amount || 0,
          line.line_amount,
          line.lot_number,
          line.serial_number,
          line.expiration_date,
          line.rejection_reason,
          line.notes
        ]);
      }
      
      // Batch insert all lines
      const placeholders = receiptLineValues.map(() => '(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').join(', ');
      const flatValues = receiptLineValues.flat();
      
      await connection.execute(`
        INSERT INTO po_receipt_lines (
          receipt_line_id, receipt_id, line_id, line_number, item_code, item_name,
          description, uom, quantity_ordered, quantity_received, quantity_accepted,
          quantity_rejected, unit_price, tax_rate, tax_amount, line_amount, lot_number, serial_number,
          expiration_date, rejection_reason, notes
        ) VALUES ${placeholders}
      `, flatValues);
    }
    
    // Recalculate PO header amount_received and status after editing GRN
    const headerId = oldValues.header_id;
    if (headerId) {
      // Recompute amount_received as sum of all receipt totals for this PO
      const [amountRows] = await connection.execute(
        `
          SELECT COALESCE(SUM(total_amount), 0) AS total_received
          FROM po_receipts
          WHERE header_id = ?
        `,
        [headerId]
      );
      const newAmountReceived = Number(amountRows[0]?.total_received) || 0;
      await connection.execute(
        `
          UPDATE po_headers
          SET amount_received = ?, updated_at = NOW()
          WHERE header_id = ?
        `,
        [newAmountReceived, headerId]
      );

      // And update PO status based on all receipts
      await updatePOStatusFromReceipts(connection, headerId);
    }
    
    // Update inventory based on new accepted quantities (always update when goods are received)
    try {
      await updateInventoryFromGRN(connection, req.params.id, false);
    } catch (inventoryError) {
      console.error('Failed to update inventory from GRN update:', inventoryError);
      // Don't fail the request if inventory update fails, but log it
    }
    
    // Log audit trail
    await logAuditTrail(connection, req.user.id, 'UPDATE', 'RECEIPT', req.params.id, oldValues, req.body);
    
    // Commit the transaction
    await connection.commit();
    connection.release();
    res.json({ message: 'Goods receipt updated successfully' });
  } catch (error) {
    if (connection) {
      await connection.rollback();
      connection.release();
    }
    console.error('Error updating goods receipt:', error);
    res.status(500).json({ error: 'Failed to update goods receipt' });
  }
});

// Delete goods receipt (soft delete)
router.delete('/receipts/:id', authenticateToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    
    // Get current values for audit trail
    const [currentResult] = await connection.execute(
      'SELECT * FROM po_receipts WHERE receipt_id = ?',
      [req.params.id]
    );
    
    if (currentResult.length === 0) {
      connection.release();
      return res.status(404).json({ error: 'Goods receipt not found' });
    }
    
    const oldValues = currentResult[0];
    
    // Reverse inventory before cancelling (reduce inventory by accepted quantities)
    try {
      await updateInventoryFromGRN(connection, req.params.id, true);
    } catch (inventoryError) {
      console.error('Failed to reverse inventory from GRN deletion:', inventoryError);
      // Don't fail the request if inventory update fails, but log it
    }
    
    // Soft delete by setting status to CANCELLED
    await connection.execute(
      'UPDATE po_receipts SET status = "CANCELLED", updated_at = NOW() WHERE receipt_id = ?',
      [req.params.id]
    );
    
    // Log audit trail
    await logAuditTrail(connection, req.user.id, 'DELETE', 'RECEIPT', req.params.id, oldValues, { status: 'CANCELLED' });
    
    connection.release();
    res.json({ message: 'Goods receipt cancelled successfully' });
  } catch (error) {
    console.error('Error cancelling goods receipt:', error);
    res.status(500).json({ error: 'Failed to cancel goods receipt' });
  }
});

// ============================================================================
// SUPPORTING DATA ENDPOINTS
// ============================================================================

// OPTIMIZED: Get suppliers for dropdowns (uses pool directly)
router.get('/suppliers', async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT supplier_id, supplier_number, supplier_name 
      FROM ap_suppliers 
      WHERE status = 'ACTIVE' 
      ORDER BY supplier_name
    `);
    res.json(rows);
  } catch (error) {
    console.error('Error fetching suppliers:', error);
    res.status(500).json({ error: 'Failed to fetch suppliers' });
  }
});

// Get supplier sites - REMOVED: This route conflicts with customer-supplier routes
// Use /api/customer-supplier/suppliers/:supplierId/sites instead

// OPTIMIZED: Get users for dropdowns (uses pool directly)
router.get('/users', async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT id, first_name, last_name, email, role 
      FROM users 
      WHERE is_active = TRUE 
      ORDER BY first_name, last_name
    `);
    res.json(rows);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// OPTIMIZED: Get purchase requisitions for dropdowns (uses pool directly)
router.get('/requisitions-dropdown', async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT requisition_id, requisition_number, description, total_amount 
      FROM po_requisitions 
      WHERE status = 'APPROVED' 
      ORDER BY created_at DESC
    `);
    res.json(rows);
  } catch (error) {
    console.error('Error fetching requisitions:', error);
    res.status(500).json({ error: 'Failed to fetch requisitions' });
  }
});

// OPTIMIZED: Get purchase agreements for dropdowns (uses pool directly)
router.get('/agreements-dropdown', async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT agreement_id, agreement_number, description, amount_remaining 
      FROM po_agreements 
      WHERE status = 'ACTIVE' AND amount_remaining > 0 
      ORDER BY created_at DESC
    `);
    res.json(rows);
  } catch (error) {
    console.error('Error fetching agreements:', error);
    res.status(500).json({ error: 'Failed to fetch agreements' });
  }
});

// OPTIMIZED: Get purchase orders for dropdowns (uses pool directly)
router.get('/purchase-orders-dropdown', async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT header_id, po_number, description, total_amount, amount_received
      FROM po_headers 
      WHERE status = 'RELEASED' AND (total_amount - amount_received) > 0 
      ORDER BY created_at DESC
    `);
    res.json(rows);
  } catch (error) {
    console.error('Error fetching purchase orders:', error);
    res.status(500).json({ error: 'Failed to fetch purchase orders' });
  }
});

// OPTIMIZED: Get PO lines for dropdowns and GRN (uses pool directly)
router.get('/purchase-orders/:headerId/lines', async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT line_id, line_number, item_code, item_name, description, uom, quantity, quantity_remaining, unit_price, line_amount
      FROM po_lines 
      WHERE header_id = ?
      ORDER BY line_number
    `, [req.params.headerId]);
    res.json(rows);
  } catch (error) {
    console.error('Error fetching PO lines:', error);
    res.status(500).json({ error: 'Failed to fetch PO lines' });
  }
});


// OPTIMIZED: Get procurement categories (uses pool directly)
router.get('/categories', async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT category_id, category_code, category_name, description 
      FROM po_categories 
      WHERE is_active = TRUE 
      ORDER BY category_name
    `);
    res.json(rows);
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
});

// OPTIMIZED: Get procurement items (uses pool directly)
router.get('/items', async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT item_id, item_code, item_name, description, category_id, uom, standard_price 
      FROM po_items 
      WHERE is_active = TRUE 
      ORDER BY item_name
    `);
    res.json(rows);
  } catch (error) {
    console.error('Error fetching items:', error);
    res.status(500).json({ error: 'Failed to fetch items' });
  }
});

// Pakistan GST PO Number Generation - Smart Logic
router.get('/generate-po-number', async (req, res) => {
  try {
    const { year } = req.query;
    const currentYear = year || new Date().getFullYear();
    
    const connection = await pool.getConnection();
    
    // Start transaction for atomicity
    await connection.beginTransaction();
    
    try {
      // Set prefix for Pakistan GST System
      const prefix = `PO-PK-${currentYear}`;
      
      // Check which PO numbers are actually used in purchase orders
      const [usedPONumbers] = await connection.execute(
        'SELECT po_number FROM po_headers WHERE po_number LIKE ? ORDER BY po_number',
        [`${prefix}-%`]
      );
      
      // Find the next available number
      let nextNumber = 1;
      const usedNumbers = usedPONumbers.map(row => {
        const match = row.po_number.match(new RegExp(`${prefix}-(\\d+)`));
        return match ? parseInt(match[1]) : 0;
      }).filter(num => num > 0).sort((a, b) => a - b);
      
      // Get all numbers from tracking table
      const [trackingNumbers] = await connection.execute(
        'SELECT po_number FROM po_numbers WHERE po_number LIKE ? ORDER BY po_number',
        [`${prefix}-%`]
      );
      
      const trackingUsedNumbers = trackingNumbers.map(row => {
        const match = row.po_number.match(new RegExp(`${prefix}-(\\d+)`));
        return match ? parseInt(match[1]) : 0;
      }).filter(num => num > 0).sort((a, b) => a - b);
      
      // Find the next number that doesn't exist in either table
      const allUsedNumbers = [...new Set([...usedNumbers, ...trackingUsedNumbers])];
      const maxNumber = Math.max(...allUsedNumbers, 0);
      
      for (let i = 1; i <= maxNumber + 1; i++) {
        if (!allUsedNumbers.includes(i)) {
          nextNumber = i;
          break;
        }
      }
      
      // Generate the PO number
      const formattedNumber = nextNumber.toString().padStart(4, '0');
      const generatedPO = `${prefix}-${formattedNumber}`;
      
      // Check if this PO number already exists in po_headers table (actual purchase orders)
      const [existingPOs] = await connection.execute(
        'SELECT COUNT(*) as count FROM po_headers WHERE po_number = ?',
        [generatedPO]
      );
      
      // Also check tracking table to avoid duplicates
      const [existingTracking] = await connection.execute(
        'SELECT COUNT(*) as count FROM po_numbers WHERE po_number = ?',
        [generatedPO]
      );
      
      if (existingPOs[0].count === 0 && existingTracking[0].count === 0) {
        // Insert generated PO number into tracking table for audit
        await connection.execute(
          'INSERT INTO po_numbers (po_number, generated_date, is_manual) VALUES (?, CURRENT_DATE, FALSE)',
          [generatedPO]
        );
        
        await connection.commit();
        connection.release();
        
        res.json({ 
          po_number: generatedPO,
          success: true,
          message: 'PO number generated successfully',
          next_available: nextNumber
        });
      } else {
        await connection.rollback();
        connection.release();
        res.status(409).json({ 
          error: 'Generated PO number already exists. Please retry.',
          success: false
        });
      }
    } catch (error) {
      await connection.rollback();
      connection.release();
      throw error;
    }
  } catch (error) {
    console.error('Error generating PO number:', error);
    res.status(500).json({ 
      error: 'Failed to generate PO number',
      success: false
    });
  }
});



// Debug endpoint to test PO update sequence
router.get('/test-po-sequence', async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    
    // Test sequence
    const testSeq = await getNextSequenceValue(connection, 'PO_LINE_ID_SEQ');
    
    await connection.rollback();
    connection.release();
    
    res.json({
      success: true,
      message: 'Sequence test successful',
      sequenceValue: testSeq,
      sequenceName: 'PO_LINE_ID_SEQ'
    });
  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (e) {}
      connection.release();
    }
    res.status(500).json({
      success: false,
      error: error.message,
      code: error.code,
      name: error.name
    });
  }
});

export default router;

