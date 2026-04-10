import express from 'express';
import pool from '../config/database.js';

const router = express.Router();

// ============================================================================
// SEGMENTS ROUTES (Accounting Segment Types)
// ============================================================================

// Get all accounting segments (ASSETS, LIABILITIES, etc.)
router.get('/accounting-segments', async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT * FROM segments WHERE status = "ACTIVE" ORDER BY segment_type'
    );
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching accounting segments:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// COA SEGMENTS ROUTES
// ============================================================================

// Get all CoA segments
router.get('/segments', async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT * FROM coa_segments WHERE status = "ACTIVE" ORDER BY created_at DESC'
    );
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching CoA segments:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get a specific CoA by ID
router.get('/segments/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await pool.execute(
      'SELECT * FROM coa_segments WHERE id = ?',
      [id]
    );
    res.json({ success: true, data: rows[0] || null });
  } catch (error) {
    console.error('Error fetching CoA:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create a new CoA with 5 segments
router.post('/segments', async (req, res) => {
  try {
    const { 
      coa_name, 
      description,
      segment_1_name,
      segment_1_value,
      segment_2_name,
      segment_2_value,
      segment_3_name,
      segment_3_value,
      segment_4_name,
      segment_4_value,
      segment_5_name,
      segment_5_value,
      segment_length,
      created_by
    } = req.body;
    
    const [result] = await pool.execute(
      `INSERT INTO coa_segments (
        coa_name, description,
        segment_1_name, segment_1_value,
        segment_2_name, segment_2_value,
        segment_3_name, segment_3_value,
        segment_4_name, segment_4_value,
        segment_5_name, segment_5_value,
        segment_length, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        coa_name,
        description || null,
        segment_1_name || null,
        segment_1_value || '00000',
        segment_2_name || null,
        segment_2_value || '00000',
        segment_3_name || null,
        segment_3_value || '00000',
        segment_4_name || null,
        segment_4_value || '00000',
        segment_5_name || null,
        segment_5_value || '00000',
        segment_length || 5,
        created_by || 1
      ]
    );
    
    res.json({ success: true, data: { id: result.insertId, ...req.body } });
  } catch (error) {
    console.error('Error creating CoA:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update a CoA
router.put('/segments/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { 
      coa_name,
      description,
      segment_1_name,
      segment_1_value,
      segment_2_name,
      segment_2_value,
      segment_3_name,
      segment_3_value,
      segment_4_name,
      segment_4_value,
      segment_5_name,
      segment_5_value,
      segment_length,
      status
    } = req.body;
    
    // Convert undefined to null for all parameters to avoid SQL errors
    // Build the base parameters array (without status and id)
    const baseParams = [
      coa_name ?? null,
      description ?? null,
      segment_1_name ?? null,
      segment_1_value ?? '00000',
      segment_2_name ?? null,
      segment_2_value ?? '00000',
      segment_3_name ?? null,
      segment_3_value ?? '00000',
      segment_4_name ?? null,
      segment_4_value ?? '00000',
      segment_5_name ?? null,
      segment_5_value ?? '00000',
      segment_length ?? 5
    ];
    
    // Build query - always include the base fields
    let query = `UPDATE coa_segments SET 
      coa_name = ?, description = ?,
      segment_1_name = ?, segment_1_value = ?,
      segment_2_name = ?, segment_2_value = ?,
      segment_3_name = ?, segment_3_value = ?,
      segment_4_name = ?, segment_4_value = ?,
      segment_5_name = ?, segment_5_value = ?,
      segment_length = ?`;
    
    // Build queryParams array starting with base params
    const queryParams = [...baseParams];
    
    // Only update status if it's provided (not null and not undefined)
    if (status !== null && status !== undefined) {
      query += ', status = ?';
      queryParams.push(status);
    }
    
    // Always add id at the end
    query += ' WHERE id = ?';
    queryParams.push(id);
    
    await pool.execute(query, queryParams);
    
    res.json({ success: true, message: 'CoA updated successfully' });
  } catch (error) {
    console.error('Error updating CoA:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete a CoA
router.delete('/segments/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await pool.execute('UPDATE coa_segments SET status = "INACTIVE" WHERE id = ?', [id]);
    res.json({ success: true, message: 'CoA deleted successfully' });
  } catch (error) {
    console.error('Error deleting CoA:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// COA SEGMENT INSTANCES ROUTES
// ============================================================================

// Create a segment instance
router.post('/segments/instances', async (req, res) => {
  try {
    const { 
      segment_id, 
      segment_code, 
      segment_name, 
      segment_type, 
      segment_use,
      is_primary,
      status,
      created_by 
    } = req.body;
    
    // Validate required fields
    if (!segment_id || !segment_code || !segment_name || !segment_type) {
      return res.status(400).json({ 
        success: false, 
        error: 'segment_id, segment_code, segment_name, and segment_type are required' 
      });
    }
    
    const [result] = await pool.execute(
      `INSERT INTO segments (
        segment_id, 
        segment_code, 
        segment_name, 
        segment_type, 
        segment_use,
        is_primary,
        status,
        created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        segment_id,
        segment_code,
        segment_name,
        segment_type,
        segment_use || null,
        is_primary || false,
        status || 'ACTIVE',
        created_by || 1
      ]
    );
    
    res.json({ 
      success: true, 
      data: { 
        id: result.insertId, 
        segment_id,
        segment_code,
        segment_name,
        segment_type,
        segment_use,
        is_primary: is_primary || false,
        status: status || 'ACTIVE'
      } 
    });
  } catch (error) {
    console.error('Error creating segment instance:', error);
    
    // Handle duplicate entry error
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ 
        success: false, 
        error: 'A segment with this ID or code already exists' 
      });
    }
    
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get all segment instances
router.get('/segments/instances', async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT * FROM segments WHERE status = "ACTIVE" ORDER BY created_at DESC'
    );
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching segment instances:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get a specific segment instance by ID
router.get('/segments/instances/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await pool.execute(
      'SELECT * FROM segments WHERE id = ?',
      [id]
    );
    
    if (rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Segment instance not found' 
      });
    }
    
    res.json({ success: true, data: rows[0] });
  } catch (error) {
    console.error('Error fetching segment instance:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update a segment instance
router.put('/segments/instances/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { 
      segment_code, 
      segment_name, 
      segment_type, 
      segment_use,
      status
    } = req.body;
    
    await pool.execute(
      `UPDATE segments 
       SET segment_code = ?, segment_name = ?, segment_type = ?, segment_use = ?, status = ?
       WHERE id = ?`,
      [segment_code, segment_name, segment_type, segment_use || null, status || 'ACTIVE', id]
    );
    
    res.json({ success: true, message: 'Segment instance updated successfully' });
  } catch (error) {
    console.error('Error updating segment instance:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete a segment instance (soft delete)
router.delete('/segments/instances/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await pool.execute(
      'UPDATE segments SET status = "INACTIVE" WHERE id = ?',
      [id]
    );
    res.json({ success: true, message: 'Segment instance deleted successfully' });
  } catch (error) {
    console.error('Error deleting segment instance:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// COA INSTANCES ROUTES
// ============================================================================

// Get all CoA instances
router.get('/instances', async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT * FROM coa_instances WHERE status = "ACTIVE" ORDER BY coa_name'
    );
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching CoA instances:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get CoA instance with segments
router.get('/instances/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const [coa] = await pool.execute('SELECT * FROM coa_instances WHERE id = ?', [id]);
    const [segments] = await pool.execute(
      'SELECT * FROM coa_segment_instances WHERE coa_instance_id = ? ORDER BY display_order',
      [id]
    );
    
    res.json({ success: true, data: { ...coa[0], segments } });
  } catch (error) {
    console.error('Error fetching CoA instance:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create a CoA instance
router.post('/instances', async (req, res) => {
  try {
    const { coa_code, coa_name, description, segments } = req.body;
    
    // Create CoA instance
    const [result] = await pool.execute(
      'INSERT INTO coa_instances (coa_code, coa_name, description, created_by) VALUES (?, ?, ?, ?)',
      [coa_code, coa_name, description || null, req.body.created_by || 1]
    );
    
    const coaInstanceId = result.insertId;
    
    // OPTIMIZED: Batch insert segments instead of individual inserts
    if (segments && segments.length > 0) {
      const segmentValues = segments.map(segment => [
        coaInstanceId,
        segment.name,
        segment.length,
        segment.display_order || 0
      ]);
      
      // Use batch insert
      const placeholders = segmentValues.map(() => '(?, ?, ?, ?)').join(', ');
      const flatValues = segmentValues.flat();
      
      await pool.execute(
        `INSERT INTO coa_segment_instances (coa_instance_id, segment_name, segment_length, display_order) VALUES ${placeholders}`,
        flatValues
      );
    }
    
    res.json({ success: true, data: { id: coaInstanceId, coa_code, coa_name, description } });
  } catch (error) {
    console.error('Error creating CoA instance:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// LEDGER CONFIGURATIONS ROUTES
// ============================================================================

// Get all ledger configurations
router.get('/ledgers', async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT lc.*, ci.coa_code, ci.coa_name 
       FROM ledger_configurations lc 
       LEFT JOIN coa_instances ci ON lc.coa_instance_id = ci.id 
       WHERE lc.status = "ACTIVE" 
       ORDER BY lc.ledger_name`
    );
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching ledgers:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create a ledger configuration
router.post('/ledgers', async (req, res) => {
  try {
    const { ledger_name, ledger_type, currency, coa_instance_id, accounting_method, ar_ap_enabled } = req.body;
    
    const [result] = await pool.execute(
      'INSERT INTO ledger_configurations (ledger_name, ledger_type, currency, coa_instance_id, accounting_method, ar_ap_enabled, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [ledger_name, ledger_type, currency, coa_instance_id, accounting_method, ar_ap_enabled || true, req.body.created_by || 1]
    );
    
    res.json({ success: true, data: { id: result.insertId, ...req.body } });
  } catch (error) {
    console.error('Error creating ledger:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update a ledger configuration
router.put('/ledgers/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { ledger_name, ledger_type, currency, accounting_method, ar_ap_enabled } = req.body;
    
    await pool.execute(
      'UPDATE ledger_configurations SET ledger_name = ?, ledger_type = ?, currency = ?, accounting_method = ?, ar_ap_enabled = ? WHERE id = ?',
      [ledger_name, ledger_type, currency, accounting_method, ar_ap_enabled, id]
    );
    
    res.json({ success: true, message: 'Ledger updated successfully' });
  } catch (error) {
    console.error('Error updating ledger:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete a ledger configuration
router.delete('/ledgers/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await pool.execute('UPDATE ledger_configurations SET status = "INACTIVE" WHERE id = ?', [id]);
    res.json({ success: true, message: 'Ledger deleted successfully' });
  } catch (error) {
    console.error('Error deleting ledger:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// HEADER ASSIGNMENTS ROUTES
// ============================================================================

// Get all header assignments for a ledger
router.get('/ledgers/:ledgerId/header-assignments', async (req, res) => {
  try {
    const { ledgerId } = req.params;
    const [rows] = await pool.execute(
      'SELECT * FROM ledger_header_assignments WHERE ledger_id = ? AND is_active = TRUE',
      [ledgerId]
    );
    
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching header assignments:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// HEADER ASSIGNMENTS ROUTES
// ============================================================================

// Get all header assignments with their relationships
router.get('/header-assignments', async (req, res) => {
  try {
    const [headerAssignments] = await pool.execute(`
      SELECT 
        ha.id,
        ha.header_id,
        ha.header_name,
        ha.coa_instance_id,
        ci.coa_code,
        ci.coa_name,
        ha.validation_rules,
        ha.is_active,
        ha.created_at,
        ha.updated_at
      FROM header_assignments ha
      LEFT JOIN coa_instances ci ON ha.coa_instance_id = ci.id
      WHERE ha.is_active = TRUE
      ORDER BY ha.created_at DESC
    `);
    
    // Get ledgers and modules for each header assignment
    for (let assignment of headerAssignments) {
      // Get assigned ledgers
      const [ledgers] = await pool.execute(`
        SELECT l.id, l.ledger_name
        FROM header_ledger_assignments hla
        JOIN ledger_configurations l ON hla.ledger_id = l.id
        WHERE hla.header_assignment_id = ? AND hla.is_active = TRUE
      `, [assignment.id]);
      assignment.ledgers = ledgers;
      
      // Get assigned modules
      const [modules] = await pool.execute(`
        SELECT module_type
        FROM header_module_assignments
        WHERE header_assignment_id = ? AND is_active = TRUE
      `, [assignment.id]);
      assignment.modules = modules.map(m => m.module_type);
    }
    
    res.json({ success: true, data: headerAssignments });
  } catch (error) {
    console.error('Error fetching header assignments:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get a specific header assignment
router.get('/header-assignments/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const [headerAssignments] = await pool.execute(`
      SELECT 
        ha.*,
        ci.coa_code,
        ci.coa_name
      FROM header_assignments ha
      LEFT JOIN coa_instances ci ON ha.coa_instance_id = ci.id
      WHERE ha.id = ?
    `, [id]);
    
    if (headerAssignments.length === 0) {
      return res.status(404).json({ success: false, error: 'Header assignment not found' });
    }
    
    const assignment = headerAssignments[0];
    
    // Get assigned ledgers
    const [ledgers] = await pool.execute(`
      SELECT l.id, l.ledger_name
      FROM header_ledger_assignments hla
      JOIN ledger_configurations l ON hla.ledger_id = l.id
      WHERE hla.header_assignment_id = ? AND hla.is_active = TRUE
    `, [id]);
    assignment.ledgers = ledgers;
    
    // Get assigned modules
    const [modules] = await pool.execute(`
      SELECT module_type
      FROM header_module_assignments
      WHERE header_assignment_id = ? AND is_active = TRUE
    `, [id]);
    assignment.modules = modules.map(m => m.module_type);
    
    res.json({ success: true, data: assignment });
  } catch (error) {
    console.error('Error fetching header assignment:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create a header assignment
router.post('/header-assignments', async (req, res) => {
  const connection = await pool.getConnection();
  
  try {
    await connection.beginTransaction();
    
    const { 
      header_id, 
      header_name, 
      coa_instance_id, 
      ledger_ids = [], 
      module_types = [], 
      validation_rules = {},
      created_by = 1 
    } = req.body;
    
    // Validate required fields
    if (!header_id || !header_name || !coa_instance_id) {
      return res.status(400).json({ 
        success: false, 
        error: 'header_id, header_name, and coa_instance_id are required' 
      });
    }
    
    // Insert main header assignment
    const [result] = await connection.execute(
      `INSERT INTO header_assignments (header_id, header_name, coa_instance_id, validation_rules, created_by) 
       VALUES (?, ?, ?, ?, ?)`,
      [header_id, header_name, coa_instance_id, JSON.stringify(validation_rules), created_by]
    );
    
    const headerAssignmentId = result.insertId;
    
    // Insert ledger assignments
    if (ledger_ids && ledger_ids.length > 0) {
      for (const ledgerId of ledger_ids) {
        await connection.execute(
          'INSERT INTO header_ledger_assignments (header_assignment_id, ledger_id) VALUES (?, ?)',
          [headerAssignmentId, ledgerId]
        );
      }
    }
    
    // Insert module assignments
    if (module_types && module_types.length > 0) {
      for (const moduleType of module_types) {
        await connection.execute(
          'INSERT INTO header_module_assignments (header_assignment_id, module_type) VALUES (?, ?)',
          [headerAssignmentId, moduleType]
        );
      }
    }
    
    await connection.commit();
    
    res.json({ 
      success: true, 
      data: { 
        id: headerAssignmentId, 
        header_id, 
        header_name,
        coa_instance_id,
        ledger_ids,
        module_types,
        validation_rules
      } 
    });
  } catch (error) {
    await connection.rollback();
    console.error('Error creating header assignment:', error);
    res.status(500).json({ success: false, error: error.message });
  } finally {
    connection.release();
  }
});

// Update a header assignment
router.put('/header-assignments/:id', async (req, res) => {
  const connection = await pool.getConnection();
  
  try {
    await connection.beginTransaction();
    
    const { id } = req.params;
    const { 
      header_name, 
      coa_instance_id, 
      ledger_ids = [], 
      module_types = [], 
      validation_rules = {},
      is_active = true
    } = req.body;
    
    // Update main header assignment
    await connection.execute(
      `UPDATE header_assignments 
       SET header_name = ?, coa_instance_id = ?, validation_rules = ?, is_active = ?
       WHERE id = ?`,
      [header_name, coa_instance_id, JSON.stringify(validation_rules), is_active, id]
    );
    
    // Delete existing ledger assignments
    await connection.execute(
      'DELETE FROM header_ledger_assignments WHERE header_assignment_id = ?',
      [id]
    );
    
    // Insert new ledger assignments
    if (ledger_ids && ledger_ids.length > 0) {
      for (const ledgerId of ledger_ids) {
        await connection.execute(
          'INSERT INTO header_ledger_assignments (header_assignment_id, ledger_id) VALUES (?, ?)',
          [id, ledgerId]
        );
      }
    }
    
    // Delete existing module assignments
    await connection.execute(
      'DELETE FROM header_module_assignments WHERE header_assignment_id = ?',
      [id]
    );
    
    // Insert new module assignments
    if (module_types && module_types.length > 0) {
      for (const moduleType of module_types) {
        await connection.execute(
          'INSERT INTO header_module_assignments (header_assignment_id, module_type) VALUES (?, ?)',
          [id, moduleType]
        );
      }
    }
    
    await connection.commit();
    
    res.json({ success: true, data: { id, ...req.body } });
  } catch (error) {
    await connection.rollback();
    console.error('Error updating header assignment:', error);
    res.status(500).json({ success: false, error: error.message });
  } finally {
    connection.release();
  }
});

// Delete a header assignment
router.delete('/header-assignments/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    await pool.execute(
      'UPDATE header_assignments SET is_active = FALSE WHERE id = ?',
      [id]
    );
    
    res.json({ success: true, message: 'Header assignment deactivated successfully' });
  } catch (error) {
    console.error('Error deleting header assignment:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

export default router;
