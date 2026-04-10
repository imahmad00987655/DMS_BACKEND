import express from 'express';
import mysql from 'mysql2/promise';
import { dbConfig } from '../config/database.js';

const router = express.Router();

// Get all parties
router.get('/', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    
    // Get parties with sites and contacts count
    const [rows] = await connection.execute(`
      SELECT 
        p.*,
        COALESCE(sites_count.count, 0) as sites_count,
        COALESCE(contacts_count.count, 0) as contacts_count
      FROM parties p
      LEFT JOIN (
        SELECT party_id, COUNT(*) as count 
        FROM party_sites 
        WHERE status = 'ACTIVE'
        GROUP BY party_id
      ) sites_count ON p.party_id = sites_count.party_id
      LEFT JOIN (
        SELECT party_id, COUNT(*) as count 
        FROM party_contact_points 
        WHERE status = 'ACTIVE'
        GROUP BY party_id
      ) contacts_count ON p.party_id = contacts_count.party_id
      ORDER BY p.created_at DESC
    `);
    
    await connection.end();
    
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching parties:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch parties' });
  }
});

// Get party by ID
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute('SELECT * FROM parties WHERE party_id = ?', [id]);
    await connection.end();
    
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Party not found' });
    }
    
    res.json({ success: true, data: rows[0] });
  } catch (error) {
    console.error('Error fetching party:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch party' });
  }
});

// Create new party
router.post('/', async (req, res) => {
  try {
    const { party_name, party_type, tax_id, website, industry, status } = req.body;
    
    if (!party_name) {
      return res.status(400).json({ success: false, message: 'Party name is required' });
    }
    
    const connection = await mysql.createConnection(dbConfig);
    
    // Get next party ID from sequence
    const [seqResult] = await connection.execute('SELECT current_value FROM ar_sequences WHERE sequence_name = "PARTY_ID_SEQ"');
    let nextId = 1;
    if (seqResult.length > 0) {
      nextId = seqResult[0].current_value;
      await connection.execute('UPDATE ar_sequences SET current_value = current_value + 1 WHERE sequence_name = "PARTY_ID_SEQ"');
    }
    
    // Generate party number
    const party_number = `P${String(nextId).padStart(6, '0')}`;
    
    // Insert party
    const [result] = await connection.execute(
      'INSERT INTO parties (party_id, party_number, party_name, party_type, tax_id, website, industry, status, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [nextId, party_number, party_name, party_type || 'ORGANIZATION', tax_id || null, website || null, industry || null, status || 'ACTIVE', req.user?.id || 1]
    );
    
    await connection.end();
    
    res.status(201).json({ 
      success: true, 
      message: 'Party created successfully',
      data: { party_id: nextId, party_number, party_name }
    });
  } catch (error) {
    console.error('Error creating party:', error);
    res.status(500).json({ success: false, message: 'Failed to create party' });
  }
});

// Update party
router.put('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { party_name, party_type, tax_id, website, industry, status } = req.body;
    
    if (!party_name) {
      return res.status(400).json({ success: false, message: 'Party name is required' });
    }
    
    const connection = await mysql.createConnection(dbConfig);
    const [result] = await connection.execute(
      'UPDATE parties SET party_name = ?, party_type = ?, tax_id = ?, website = ?, industry = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE party_id = ?',
      [party_name, party_type, tax_id, website, industry, status, id]
    );
    
    await connection.end();
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Party not found' });
    }
    
    res.json({ success: true, message: 'Party updated successfully' });
  } catch (error) {
    console.error('Error updating party:', error);
    res.status(500).json({ success: false, message: 'Failed to update party' });
  }
});

// Delete party
router.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const connection = await mysql.createConnection(dbConfig);
    
    // Check if party has any sites
    const [sites] = await connection.execute('SELECT COUNT(*) as count FROM party_sites WHERE party_id = ?', [id]);
    
    if (sites[0].count > 0) {
      await connection.end();
      return res.status(400).json({ 
        success: false, 
        message: 'Cannot delete party with existing sites. Delete sites first.' 
      });
    }
    
    const [result] = await connection.execute('DELETE FROM parties WHERE party_id = ?', [id]);
    await connection.end();
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Party not found' });
    }
    
    res.json({ success: true, message: 'Party deleted successfully' });
  } catch (error) {
    console.error('Error deleting party:', error);
    res.status(500).json({ success: false, message: 'Failed to delete party' });
  }
});

// Get party sites
router.get('/:id/sites', async (req, res) => {
  try {
    const { id } = req.params;
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute('SELECT * FROM party_sites WHERE party_id = ? ORDER BY is_primary DESC, created_at DESC', [id]);
    await connection.end();
    
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching party sites:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch party sites' });
  }
});

// Create party site
router.post('/:id/sites', async (req, res) => {
  try {
    const { id } = req.params;
    const { site_name, site_type, address_line1, address_line2, city, state, postal_code, country, phone, email, contact_person, is_primary } = req.body;
    
    if (!site_name) {
      return res.status(400).json({ success: false, message: 'Site name is required' });
    }
    
    const connection = await mysql.createConnection(dbConfig);
    
    // Get next site ID from sequence
    const [seqResult] = await connection.execute('SELECT current_value FROM ar_sequences WHERE sequence_name = "PARTY_SITE_ID_SEQ"');
    let nextId = 1;
    if (seqResult.length > 0) {
      nextId = seqResult[0].current_value;
      await connection.execute('UPDATE ar_sequences SET current_value = current_value + 1 WHERE sequence_name = "PARTY_SITE_ID_SEQ"');
    }
    
    // If this is primary site, unset other primary sites
    if (is_primary) {
      await connection.execute('UPDATE party_sites SET is_primary = FALSE WHERE party_id = ?', [id]);
    }
    
    // Insert site
    const [result] = await connection.execute(
      'INSERT INTO party_sites (site_id, party_id, site_name, site_type, address_line1, address_line2, city, state, postal_code, country, phone, email, contact_person, is_primary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [nextId, id, site_name, site_type || 'BOTH', address_line1 || null, address_line2 || null, city || null, state || null, postal_code || null, country || null, phone || null, email || null, contact_person || null, is_primary || false]
    );
    
    await connection.end();
    
    res.status(201).json({ 
      success: true, 
      message: 'Party site created successfully',
      data: { site_id: nextId, site_name }
    });
  } catch (error) {
    console.error('Error creating party site:', error);
    console.error('Error details:', {
      message: error.message,
      code: error.code,
      sqlMessage: error.sqlMessage,
      sqlState: error.sqlState
    });
    res.status(500).json({ 
      success: false, 
      message: 'Failed to create party site',
      error: error.message,
      details: error.sqlMessage || error.message
    });
  }
});

// Update party site
router.put('/sites/:siteId', async (req, res) => {
  try {
    const { siteId } = req.params;
    const { site_name, site_type, address_line1, address_line2, city, state, postal_code, country, phone, email, contact_person, is_primary, status } = req.body;
    
    if (!site_name) {
      return res.status(400).json({ success: false, message: 'Site name is required' });
    }
    
    const connection = await mysql.createConnection(dbConfig);
    
    // If this is primary site, unset other primary sites for the same party
    if (is_primary) {
      const [siteInfo] = await connection.execute('SELECT party_id FROM party_sites WHERE site_id = ?', [siteId]);
      if (siteInfo.length > 0) {
        await connection.execute('UPDATE party_sites SET is_primary = FALSE WHERE party_id = ? AND site_id != ?', [siteInfo[0].party_id, siteId]);
      }
    }
    
    // Update site including status
    const [result] = await connection.execute(
      'UPDATE party_sites SET site_name = ?, site_type = ?, address_line1 = ?, address_line2 = ?, city = ?, state = ?, postal_code = ?, country = ?, phone = ?, email = ?, contact_person = ?, is_primary = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE site_id = ?',
      [site_name, site_type, address_line1 || null, address_line2 || null, city || null, state || null, postal_code || null, country || null, phone || null, email || null, contact_person || null, is_primary || false, status || 'ACTIVE', siteId]
    );
    
    await connection.end();
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Site not found' });
    }
    
    res.json({ success: true, message: 'Site updated successfully' });
  } catch (error) {
    console.error('Error updating party site:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to update party site',
      error: error.message,
      details: error.sqlMessage || error.message
    });
  }
});



// Get party contact points
router.get('/:id/contacts', async (req, res) => {
  try {
    const { id } = req.params;
    const connection = await mysql.createConnection(dbConfig);
    
    const [rows] = await connection.execute(
      'SELECT * FROM party_contact_points WHERE party_id = ? ORDER BY is_primary DESC, contact_point_id',
      [id]
    );
    
    await connection.end();
    
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching party contact points:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch party contact points' });
  }
});

// Create party contact point
router.post('/:id/contacts', async (req, res) => {
  try {
    const { id } = req.params;
    const { contact_point_type, contact_point_value, contact_point_purpose, is_primary, status } = req.body;
    
    if (!contact_point_type || !contact_point_value) {
      return res.status(400).json({ success: false, message: 'Contact type and value are required' });
    }
    
    const connection = await mysql.createConnection(dbConfig);
    
    // If this is primary contact, unset other primary contacts for the same party
    if (is_primary) {
      await connection.execute(
        'UPDATE party_contact_points SET is_primary = FALSE WHERE party_id = ?',
        [id]
      );
    }
    
    // Get next contact point ID from sequence
    const [seqResult] = await connection.execute('SELECT current_value FROM ar_sequences WHERE sequence_name = "PARTY_CONTACT_POINT_ID_SEQ"');
    let nextId = 1;
    if (seqResult.length > 0) {
      nextId = seqResult[0].current_value;
      await connection.execute('UPDATE ar_sequences SET current_value = current_value + 1 WHERE sequence_name = "PARTY_CONTACT_POINT_ID_SEQ"');
    }
    
    // Insert contact point
    const [result] = await connection.execute(
      'INSERT INTO party_contact_points (contact_point_id, party_id, contact_point_type, contact_point_value, contact_point_purpose, is_primary, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [nextId, id, contact_point_type, contact_point_value, contact_point_purpose || null, is_primary || false, status || 'ACTIVE']
    );
    
    await connection.end();
    
    res.status(201).json({ 
      success: true, 
      message: 'Party contact point created successfully',
      data: { contact_point_id: nextId, contact_point_type, contact_point_value }
    });
  } catch (error) {
    console.error('Error creating party contact point:', error);
    res.status(500).json({ success: false, message: 'Failed to create party contact point' });
  }
});

// Update party contact point
router.put('/contacts/:contactId', async (req, res) => {
  try {
    const { contactId } = req.params;
    const { contact_point_type, contact_point_value, contact_point_purpose, is_primary, status } = req.body;
    
    if (!contact_point_type || !contact_point_value) {
      return res.status(400).json({ success: false, message: 'Contact type and value are required' });
    }
    
    const connection = await mysql.createConnection(dbConfig);
    
    // If this is primary contact, unset other primary contacts for the same party
    if (is_primary) {
      const [contactInfo] = await connection.execute('SELECT party_id FROM party_contact_points WHERE contact_point_id = ?', [contactId]);
      if (contactInfo.length > 0) {
        await connection.execute(
          'UPDATE party_contact_points SET is_primary = FALSE WHERE party_id = ? AND contact_point_id != ?',
          [contactInfo[0].party_id, contactId]
        );
      }
    }
    
    // Update contact point
    const [result] = await connection.execute(
      'UPDATE party_contact_points SET contact_point_type = ?, contact_point_value = ?, contact_point_purpose = ?, is_primary = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE contact_point_id = ?',
      [contact_point_type, contact_point_value, contact_point_purpose || null, is_primary || false, status || 'ACTIVE', contactId]
    );
    
    await connection.end();
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Contact point not found' });
    }
    
    res.json({ success: true, message: 'Contact point updated successfully' });
  } catch (error) {
    console.error('Error updating party contact point:', error);
    res.status(500).json({ success: false, message: 'Failed to update party contact point' });
  }
});

export default router;
