import express from 'express';
import mysql from 'mysql2/promise';
import { dbConfig } from '../config/database.js';

const router = express.Router();

// Helper function to get next sequence value
const getNextSequenceValue = async (connection, sequenceName) => {
  // Determine which sequences table to use based on the sequence name
  const tableName = sequenceName.startsWith('AP_') ? 'ap_sequences' : 'ar_sequences';
  
  const [seqResult] = await connection.execute(
    `SELECT current_value FROM ${tableName} WHERE sequence_name = ?`,
    [sequenceName]
  );
  
  if (seqResult.length === 0) {
    throw new Error(`Sequence ${sequenceName} not found in ${tableName}`);
  }
  
  const currentValue = seqResult[0].current_value;
  
  // Update sequence for next use
  await connection.execute(
    `UPDATE ${tableName} SET current_value = current_value + 1 WHERE sequence_name = ?`,
    [sequenceName]
  );
  
  return currentValue;
};

// ============================================================================
// TEST ROUTE
// ============================================================================

// Test route to check if routing is working
router.get('/test', (req, res) => {
  res.json({ message: 'Customer supplier routes are working!', timestamp: new Date().toISOString() });
});

// Simple test route for supplier site creation
router.post('/test-simple', async (req, res) => {
  console.log('🧪 Simple test route hit!');
  res.json({ message: 'Simple test route working!', body: req.body });
});

// Test supplier site creation route
router.post('/test-supplier-site', async (req, res) => {
  try {
    console.log('🧪 Test route hit!');
    console.log('📦 Request body:', JSON.stringify(req.body, null, 2));
    
    const connection = await mysql.createConnection(dbConfig);
    
    // Get next site ID from sequence
    const siteId = await getNextSequenceValue(connection, 'AP_SUPPLIER_SITE_ID_SEQ');
    console.log('🆔 Generated site ID:', siteId);
    
    // Test data
    const testData = {
      site_name: 'Test Site',
      site_type: 'BILL_TO',
      address_line1: '123 Test Street',
      city: 'Test City',
      country: 'Pakistan',
      phone: '123456789',
      email: 'test@example.com',
      contact_person: 'Test Contact',
      is_primary: false,
      status: 'ACTIVE'
    };
    
    console.log('💾 Executing INSERT with test data...');
    await connection.execute(`
      INSERT INTO ap_supplier_sites (
        site_id, supplier_id, site_name, site_type, address_line1,
        city, state, postal_code, country, phone, email, contact_person,
        is_primary, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [siteId, 23, testData.site_name, testData.site_type, testData.address_line1,
        testData.city, null, null, testData.country, testData.phone, testData.email, testData.contact_person,
        testData.is_primary ? 1 : 0, testData.status]);
    
    console.log('✅ Test site created successfully!');
    await connection.end();
    
    // Clean up
    const cleanupConnection = await mysql.createConnection(dbConfig);
    await cleanupConnection.execute('DELETE FROM ap_supplier_sites WHERE site_id = ?', [siteId]);
    await cleanupConnection.end();
    
    res.json({ 
      message: 'Test supplier site created and cleaned up successfully',
      site_id: siteId
    });
  } catch (error) {
    console.error('❌ Error in test route:', error);
    console.error('❌ Error stack:', error.stack);
    res.status(500).json({ error: 'Test failed', details: error.message });
  }
});

// ============================================================================
// PARTY MANAGEMENT
// ============================================================================

// Get all parties
router.get('/parties', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    
    const [rows] = await connection.execute(`
      SELECT 
        p.party_id,
        p.party_number,
        p.party_name,
        p.party_type,
        p.tax_id,
        p.website,
        p.industry,
        p.status,
        p.created_at,
        COALESCE(site_counts.site_count, 0) as site_count,
        COALESCE(customer_counts.customer_profile_count, 0) as customer_profile_count,
        COALESCE(supplier_counts.supplier_profile_count, 0) as supplier_profile_count
      FROM parties p
      LEFT JOIN (
        SELECT party_id, COUNT(*) as site_count
        FROM party_sites
        WHERE status = 'ACTIVE'
        GROUP BY party_id
      ) site_counts ON p.party_id = site_counts.party_id
      LEFT JOIN (
        SELECT party_id, COUNT(*) as customer_profile_count
        FROM ar_customers
        WHERE status = 'ACTIVE'
        GROUP BY party_id
      ) customer_counts ON p.party_id = customer_counts.party_id
      LEFT JOIN (
        SELECT party_id, COUNT(*) as supplier_profile_count
        FROM ap_suppliers
        WHERE status = 'ACTIVE'
        GROUP BY party_id
      ) supplier_counts ON p.party_id = supplier_counts.party_id
      ORDER BY p.party_name
    `);
    
    await connection.end();
    res.json(rows);
  } catch (error) {
    console.error('Error fetching parties:', error);
    res.status(500).json({ error: 'Failed to fetch parties' });
  }
});

// Get party by ID
router.get('/parties/:id', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(
      'SELECT * FROM parties WHERE party_id = ?',
      [req.params.id]
    );
    
    await connection.end();
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Party not found' });
    }
    
    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching party:', error);
    res.status(500).json({ error: 'Failed to fetch party' });
  }
});

// Create new party
router.post('/parties', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    
    // Get next party ID from sequence using MySQL approach
    const partyId = await getNextSequenceValue(connection, 'PARTY_ID_SEQ');
    
    // Generate party number
    const partyNumber = `P${partyId.toString().padStart(6, '0')}`;
    
    const { party_name, party_type, tax_id, website, industry, status } = req.body;
    
    await connection.execute(`
      INSERT INTO parties (
        party_id, party_number, party_name, party_type, 
        tax_id, website, industry, status, created_by, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
    `, [partyId, partyNumber, party_name, party_type, tax_id, website, industry, status, 1]);
    
    await connection.end();
    res.status(201).json({ 
      message: 'Party created successfully',
      party_id: partyId,
      party_number: partyNumber
    });
  } catch (error) {
    console.error('Error creating party:', error);
    res.status(500).json({ error: 'Failed to create party' });
  }
});

// Update party
router.put('/parties/:id', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const { party_name, party_type, tax_id, website, industry, status } = req.body;
    
    await connection.execute(`
      UPDATE parties 
      SET party_name = ?, party_type = ?, tax_id = ?, 
          website = ?, industry = ?, status = ?
      WHERE party_id = ?
    `, [party_name, party_type, tax_id, website, industry, status, req.params.id]);
    
    await connection.end();
    res.json({ message: 'Party updated successfully' });
  } catch (error) {
    console.error('Error updating party:', error);
    res.status(500).json({ error: 'Failed to update party' });
  }
});

// Delete party
router.delete('/parties/:id', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    
    // Check if party has any profiles for warning purposes
    const [profiles] = await connection.execute(`
      SELECT 
        (SELECT COUNT(*) FROM ar_customers WHERE party_id = ?) as customer_count,
        (SELECT COUNT(*) FROM ap_suppliers WHERE party_id = ?) as supplier_count
    `, [req.params.id, req.params.id]);
    
    // Delete associated profiles first (cascade delete)
    if (profiles[0].customer_count > 0) {
      await connection.execute('DELETE FROM ar_customers WHERE party_id = ?', [req.params.id]);
    }
    
    if (profiles[0].supplier_count > 0) {
      await connection.execute('DELETE FROM ap_suppliers WHERE party_id = ?', [req.params.id]);
    }
    
    // Delete party sites
    await connection.execute('DELETE FROM party_sites WHERE party_id = ?', [req.params.id]);
    
    // Delete contact points
    await connection.execute('DELETE FROM party_contact_points WHERE party_id = ?', [req.params.id]);
    
    // Finally delete the party
    await connection.execute('DELETE FROM parties WHERE party_id = ?', [req.params.id]);
    
    await connection.end();
    
    const message = profiles[0].customer_count > 0 || profiles[0].supplier_count > 0
      ? `Party and all associated profiles (${profiles[0].customer_count} customer, ${profiles[0].supplier_count} supplier) deleted successfully`
      : 'Party deleted successfully';
    
    res.json({ message });
  } catch (error) {
    console.error('Error deleting party:', error);
    res.status(500).json({ error: 'Failed to delete party' });
  }
});

// ============================================================================
// PARTY SITES MANAGEMENT
// ============================================================================

// Get party sites
router.get('/parties/:partyId/sites', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(
      'SELECT * FROM party_sites WHERE party_id = ? ORDER BY is_primary DESC, site_name',
      [req.params.partyId]
    );
    
    await connection.end();
    res.json(rows);
  } catch (error) {
    console.error('Error fetching party sites:', error);
    res.status(500).json({ error: 'Failed to fetch party sites' });
  }
});

// Create party site
router.post('/parties/:partyId/sites', async (req, res) => {
  try {
    console.log('🔍 Creating party site for party ID:', req.params.partyId);
    console.log('📦 Request body:', JSON.stringify(req.body, null, 2));
    
    const connection = await mysql.createConnection(dbConfig);
    
    // Get next site ID from sequence
    const siteId = await getNextSequenceValue(connection, 'HZ_PARTY_SITE_ID_SEQ');
    console.log('🆔 Generated site ID:', siteId);
    
    const {
      site_name, site_type, address_line1, address_line2, city, state, postal_code,
      country, is_primary, status
    } = req.body;
    
    console.log('📋 Extracted data:', {
      site_name, site_type, address_line1, address_line2, city, state, postal_code,
      country, is_primary, status
    });
    
    // If this is primary, unset other primary sites
    if (is_primary) {
      console.log('🔄 Unsetting other primary sites...');
      await connection.execute(
        'UPDATE party_sites SET is_primary = FALSE WHERE party_id = ?',
        [req.params.partyId]
      );
    }
    
    console.log('💾 Executing INSERT...');
    await connection.execute(`
      INSERT INTO party_sites (
        site_id, party_id, site_name, site_type, address_line1,
        address_line2, city, state, postal_code, country, 
        is_primary, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [siteId, req.params.partyId, site_name, site_type, address_line1,
        address_line2, city, state, postal_code, country,
        is_primary, status]);
    
    console.log('✅ Site created successfully!');
    await connection.end();
    res.status(201).json({ 
      message: 'Party site created successfully',
      site_id: siteId
    });
  } catch (error) {
    console.error('❌ Error creating party site:', error);
    console.error('❌ Error stack:', error.stack);
    res.status(500).json({ error: 'Failed to create party site' });
  }
});

// Update party site
router.put('/sites/:siteId', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const {
      site_name, site_type, address_line1, address_line2, city, state, postal_code,
      country, is_primary, status
    } = req.body;
    
    // If this is primary, unset other primary sites for the same party
    if (is_primary) {
      const [siteResult] = await connection.execute(
        'SELECT party_id FROM party_sites WHERE site_id = ?',
        [req.params.siteId]
      );
      if (siteResult.length > 0) {
        await connection.execute(
          'UPDATE party_sites SET is_primary = FALSE WHERE party_id = ? AND site_id != ?',
          [siteResult[0].party_id, req.params.siteId]
        );
      }
    }
    
    await connection.execute(`
      UPDATE party_sites 
      SET site_name = ?, site_type = ?, address_line1 = ?, address_line2 = ?, city = ?,
          state = ?, postal_code = ?, country = ?, is_primary = ?, status = ?
      WHERE site_id = ?
    `, [site_name, site_type, address_line1, address_line2, city, state, postal_code,
        country, is_primary, status, req.params.siteId]);
    
    await connection.end();
    res.json({ message: 'Party site updated successfully' });
  } catch (error) {
    console.error('Error updating party site:', error);
    res.status(500).json({ error: 'Failed to update party site' });
  }
});

// Delete party site
router.delete('/sites/:siteId', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
          await connection.execute('DELETE FROM party_sites WHERE site_id = ?', [req.params.siteId]);
    await connection.end();
    res.json({ message: 'Party site deleted successfully' });
  } catch (error) {
    console.error('Error deleting party site:', error);
    res.status(500).json({ error: 'Failed to delete party site' });
  }
});

// ============================================================================
// CUSTOMER PROFILES MANAGEMENT
// ============================================================================

// Get all customers
router.get('/customers', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    
    const [rows] = await connection.execute(`
      SELECT 
        c.customer_id as profile_id,
        c.party_id,
        c.customer_number,
        c.customer_name,
        c.customer_type,
        c.customer_class,
        c.customer_category,
        c.tax_id,
        c.credit_limit,
        c.credit_hold_flag,
        c.payment_terms_id,
        c.status,
        c.created_at,
        c.updated_at,
        p.party_name,
        p.party_type,
        p.tax_id as party_tax_id,
        p.website,
        p.industry,
        p.party_number as party_no
      FROM ar_customers c
      LEFT JOIN parties p ON c.party_id = p.party_id
      ORDER BY c.created_at DESC
    `);
    
    await connection.end();
    res.json(rows);
  } catch (error) {
    console.error('Error fetching customers:', error);
    res.status(500).json({ error: 'Failed to fetch customers' });
  }
});

// Get customer by ID
router.get('/customers/:id', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(`
      SELECT 
        c.customer_id,
        c.customer_number,
        c.party_id,
        c.customer_name,
        c.customer_type,
        c.customer_class,
        c.customer_category,
        c.tax_id,
        c.credit_limit,
        c.credit_hold_flag,
        c.payment_terms_id,
        c.status,
        c.created_by,
        c.created_at,
        c.updated_at,
        p.party_name,
        p.party_type,
        p.tax_id as party_tax_id,
        p.website,
        p.industry,
        p.party_number as party_no
      FROM ar_customers c
      LEFT JOIN parties p ON c.party_id = p.party_id
      WHERE c.customer_id = ?
    `, [req.params.id]);
    
    await connection.end();
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Customer not found' });
    }
    
    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching customer:', error);
    res.status(500).json({ error: 'Failed to fetch customer' });
  }
});

// Create customer profile
router.post('/customers', async (req, res) => {
  try {
    console.log('🔍 Creating customer profile...');
    console.log('📦 Request body:', JSON.stringify(req.body, null, 2));
    
    const connection = await mysql.createConnection(dbConfig);
    console.log('✅ Database connection established');
    
    // Get next customer ID from sequence
    let profileId;
    try {
      console.log('🔍 Getting next sequence value...');
      profileId = await getNextSequenceValue(connection, 'AR_CUSTOMER_ID_SEQ');
      console.log('🆔 Generated profile ID:', profileId);
    } catch (seqError) {
      console.error('❌ Error getting sequence:', seqError);
      await connection.end();
      return res.status(500).json({ error: 'Failed to get sequence value' });
    }
    
    // Generate customer number
    const customerNumber = `C${profileId.toString().padStart(6, '0')}`;
    console.log('📋 Generated customer number:', customerNumber);
    
    const {
      party_id, customer_name, customer_type, customer_class, customer_category,
      credit_limit, credit_hold_flag, payment_terms_id,
      status
    } = req.body;
    
    console.log('📋 Extracted data:', {
      party_id, customer_name, customer_type, customer_class, customer_category,
      credit_limit, credit_hold_flag, payment_terms_id,
      status
    });
    
    // Validate customer_type
    const validCustomerTypes = ['INDIVIDUAL', 'CORPORATE', 'GOVERNMENT', 'NON_PROFIT'];
    if (!customer_type || typeof customer_type !== 'string' || customer_type.trim() === '') {
      await connection.end();
      return res.status(400).json({ 
        error: 'Customer type is required and must be one of: INDIVIDUAL, CORPORATE, GOVERNMENT' 
      });
    }
    
    const normalizedCustomerType = customer_type.trim().toUpperCase();
    if (!validCustomerTypes.includes(normalizedCustomerType)) {
      await connection.end();
      return res.status(400).json({ 
        error: `Invalid customer type: "${customer_type}". Must be one of: INDIVIDUAL, CORPORATE, GOVERNMENT` 
      });
    }
    
    console.log('✅ Validated customer_type:', normalizedCustomerType);
    
    // Get party information to extract tax_id
    console.log('🔍 Looking up party with ID:', party_id);
    const [partyResult] = await connection.execute(
      'SELECT tax_id FROM parties WHERE party_id = ?',
      [party_id]
    );
    
    console.log('🔍 Party lookup result:', partyResult);
    
    if (partyResult.length === 0) {
      console.log('❌ Party not found with ID:', party_id);
      await connection.end();
      return res.status(400).json({ error: 'Selected party not found' });
    }
    
    const party = partyResult[0];
    // Use tax_id from form data if provided and not empty, otherwise use party's tax_id
    const customer_tax_id = req.body.tax_id && req.body.tax_id.trim() !== '' ? req.body.tax_id : party.tax_id;
    
    console.log('🔍 Party found:', party);
    console.log('🔍 Creating customer with party_id:', party_id);
    console.log('🔍 Customer name from form:', customer_name);
    console.log('🔍 Tax ID will be:', customer_tax_id);
    
    console.log('💾 Executing INSERT...');
    await connection.execute(`
      INSERT INTO ar_customers (
        customer_id, customer_number, party_id, customer_name, customer_type,
        customer_class, customer_category, tax_id, credit_limit, credit_hold_flag, payment_terms_id,
        status, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [profileId, customerNumber, party_id, customer_name, normalizedCustomerType, customer_class, customer_category,
        customer_tax_id, credit_limit, credit_hold_flag, payment_terms_id, status, 1]);
    
    console.log('✅ Customer profile created successfully!');
    await connection.end();
    res.status(201).json({ 
      message: 'Customer profile created successfully',
      profile_id: profileId,
      customer_number: customerNumber
    });
  } catch (error) {
    console.error('❌ Error creating customer profile:', error);
    console.error('❌ Error stack:', error.stack);
    res.status(500).json({ error: 'Failed to create customer profile' });
  }
});

// Update customer profile
router.put('/customers/:id', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const {
      party_id, customer_name, customer_type, customer_class, customer_category, credit_limit,
      credit_hold_flag, payment_terms_id,
      tax_id, status
    } = req.body;
    
    // Get party information to extract tax_id
    if (party_id) {
      const [partyResult] = await connection.execute(
        'SELECT tax_id FROM parties WHERE party_id = ?',
        [party_id]
      );
      
      if (partyResult.length === 0) {
        await connection.end();
        return res.status(400).json({ error: 'Selected party not found' });
      }
      
      const party = partyResult[0];
      // Use tax_id from form data if provided and not empty, otherwise use party's tax_id
      const customer_tax_id = req.body.tax_id && req.body.tax_id.trim() !== '' ? req.body.tax_id : party.tax_id;
      
      await connection.execute(`
        UPDATE ar_customers 
        SET party_id = ?, customer_name = ?, customer_type = ?, customer_class = ?, customer_category = ?, tax_id = ?,
            credit_limit = ?, credit_hold_flag = ?, payment_terms_id = ?,
            status = ?
        WHERE customer_id = ?
      `, [party_id, customer_name, customer_type, customer_class, customer_category, customer_tax_id, credit_limit,
          credit_hold_flag, payment_terms_id, status, req.params.id]);
    } else {
      await connection.execute(`
        UPDATE ar_customers 
        SET customer_name = ?, customer_type = ?, customer_class = ?, customer_category = ?, credit_limit = ?, credit_hold_flag = ?, payment_terms_id = ?,
            status = ?
        WHERE customer_id = ?
      `, [customer_name, customer_type, customer_class, customer_category, credit_limit, credit_hold_flag, payment_terms_id,
          status, req.params.id]);
    }
    
    await connection.end();
    res.json({ message: 'Customer profile updated successfully' });
  } catch (error) {
    console.error('Error updating customer profile:', error);
    res.status(500).json({ error: 'Failed to update customer profile' });
  }
});

// Delete customer profile
router.delete('/customers/:id', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    
    // Get party_id before deleting
    const [customerResult] = await connection.execute(
      'SELECT party_id FROM ar_customers WHERE customer_id = ?',
      [req.params.id]
    );
    
    if (customerResult.length === 0) {
      await connection.end();
      return res.status(404).json({ error: 'Customer profile not found' });
    }
    
    const partyId = customerResult[0].party_id;
    
    // Delete the customer profile
    await connection.execute('DELETE FROM hz_customer_profiles WHERE profile_id = ?', [req.params.id]);
    
    await connection.end();
    res.json({ message: 'Customer profile deleted successfully' });
  } catch (error) {
    console.error('Error deleting customer profile:', error);
    res.status(500).json({ error: 'Failed to delete customer profile' });
  }
});

// ============================================================================
// CUSTOMER SITES MANAGEMENT
// ============================================================================

// Get customer sites
router.get('/customers/:customerId/sites', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(`
      SELECT 
        site_id, customer_id, site_name, site_type, address_line1, address_line2,
        city, state, postal_code, country, phone, email, contact_person,
        is_primary, status, created_at, updated_at
      FROM ar_customer_sites 
      WHERE customer_id = ? 
      ORDER BY is_primary DESC, site_name
    `, [req.params.customerId]);
    
    await connection.end();
    res.json({ data: rows });
  } catch (error) {
    console.error('Error fetching customer sites:', error);
    res.status(500).json({ error: 'Failed to fetch customer sites' });
  }
});

// Create customer site
router.post('/customers/:customerId/sites', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    
    // Get next site ID from sequence
    const siteId = await getNextSequenceValue(connection, 'AR_CUSTOMER_SITE_ID_SEQ');
    
    const {
      site_name, site_type, address_line1, address_line2, city, state,
      postal_code, country, phone, email, contact_person, is_primary, status
    } = req.body;
    
    // If this is primary, unset other primary sites
    if (is_primary) {
      await connection.execute(`
        UPDATE ar_customer_sites 
        SET is_primary = 0 
        WHERE customer_id = ?
      `, [req.params.customerId]);
    }
    
    await connection.execute(`
      INSERT INTO ar_customer_sites (
        site_id, customer_id, site_name, site_type, address_line1, address_line2,
        city, state, postal_code, country, phone, email, contact_person,
        is_primary, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [siteId, req.params.customerId, site_name, site_type, address_line1, address_line2,
        city, state, postal_code, country, phone, email, contact_person,
        is_primary? 1 : 0, status]);
    
    await connection.end();
    res.status(201).json({ 
      message: 'Customer site created successfully',
      site_id: siteId
    });
  } catch (error) {
    console.error('Error creating customer site:', error);
    res.status(500).json({ error: 'Failed to create customer site' });
  }
});

// Update customer site
router.put('/customers/sites/:siteId', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    
    const {
      site_name, site_type, address_line1, address_line2, city, state,
      postal_code, country, phone, email, contact_person, is_primary, status
    } = req.body;
    
    // Get customer_id for this site
    const [siteResult] = await connection.execute(
      'SELECT customer_id FROM ar_customer_sites WHERE site_id = ?',
      [req.params.siteId]
    );
    
    if (siteResult.length === 0) {
      await connection.end();
      return res.status(404).json({ error: 'Site not found' });
    }
    
    const customerId = siteResult[0].customer_id;
    
    // If this is primary, unset other primary sites
    if (is_primary) {
      await connection.execute(`
        UPDATE ar_customer_sites 
        SET is_primary = 0 
        WHERE customer_id = ? AND site_id != ?
      `, [customerId, req.params.siteId]);
    }
    
    await connection.execute(`
      UPDATE ar_customer_sites 
      SET site_name = ?, site_type = ?, address_line1 = ?, address_line2 = ?,
          city = ?, state = ?, postal_code = ?, country = ?, phone = ?, email = ?,
          contact_person = ?, is_primary = ?, status = ?
      WHERE site_id = ?
    `, [site_name, site_type, address_line1, address_line2, city, state,
        postal_code, country, phone, email, contact_person, is_primary, status,
        req.params.siteId]);
    
    await connection.end();
    res.json({ message: 'Customer site updated successfully' });
  } catch (error) {
    console.error('Error updating customer site:', error);
    res.status(500).json({ error: 'Failed to update customer site' });
  }
});

// Delete customer site
router.delete('/customers/sites/:siteId', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    
    // Check if site exists
    const [siteResult] = await connection.execute(
      'SELECT site_id FROM ar_customer_sites WHERE site_id = ?',
      [req.params.siteId]
    );
    
    if (siteResult.length === 0) {
      await connection.end();
      return res.status(404).json({ error: 'Site not found' });
    }
    
    // Delete the site
    await connection.execute('DELETE FROM ar_customer_sites WHERE site_id = ?', [req.params.siteId]);
    
    await connection.end();
    res.json({ message: 'Customer site deleted successfully' });
  } catch (error) {
    console.error('Error deleting customer site:', error);
    res.status(500).json({ error: 'Failed to delete customer site' });
  }
});

// ============================================================================
// SUPPLIER SITES MANAGEMENT
// ============================================================================

// Test endpoint for supplier sites
router.get('/suppliers/:supplierId/sites/test', (req, res) => {
  res.json({ 
    message: 'Supplier sites test endpoint working!', 
    supplierId: req.params.supplierId,
    timestamp: new Date().toISOString()
  });
});

// Get supplier sites
router.get('/suppliers/:supplierId/sites', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(`
      SELECT 
        site_id, supplier_id, site_name, site_type, address_line1,
        city, state, postal_code, country, phone, email, contact_person,
        is_primary, status, created_at, updated_at
      FROM ap_supplier_sites 
      WHERE supplier_id = ? 
      ORDER BY is_primary DESC, site_name
    `, [req.params.supplierId]);
    
    await connection.end();
    res.json({ data: rows });
  } catch (error) {
    console.error('Error fetching supplier sites:', error);
    res.status(500).json({ error: 'Failed to fetch supplier sites' });
  }
});

// Get supplier site by ID
router.get('/sites/:siteId', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(`
      SELECT 
        site_id, supplier_id, site_name, site_type, address_line1,
        city, state, postal_code, country, phone, email, contact_person,
        is_primary, status, created_at, updated_at
      FROM ap_supplier_sites 
      WHERE site_id = ?
    `, [req.params.siteId]);
    
    await connection.end();
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Site not found' });
    }
    
    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching supplier site:', error);
    res.status(500).json({ error: 'Failed to fetch supplier site' });
  }
});

// Create supplier site
router.post('/suppliers/:supplierId/sites', async (req, res) => {
  try {
    console.log('🔍 Creating supplier site for supplier ID:', req.params.supplierId);
    console.log('📦 Request body:', JSON.stringify(req.body, null, 2));
    
    const connection = await mysql.createConnection(dbConfig);
    
    // Get next site ID from sequence
    const siteId = await getNextSequenceValue(connection, 'AP_SUPPLIER_SITE_ID_SEQ');
    console.log('🆔 Generated site ID:', siteId);
    
    const {
      site_name, site_type, address_line1, address_line2, city, state,
      postal_code, country, phone, email, contact_person, is_primary, status
    } = req.body;
    
    console.log('📋 Extracted data:', {
      site_name, site_type, address_line1, address_line2, city, state,
      postal_code, country, phone, email, contact_person, is_primary, status
    });
    
    // If this is primary, unset other primary sites
    if (is_primary) {
      console.log('🔄 Unsetting other primary sites...');
      await connection.execute(`
        UPDATE ap_supplier_sites 
        SET is_primary = 0 
        WHERE supplier_id = ?
      `, [req.params.supplierId]);
    }
    
    console.log('💾 Executing INSERT...');
    await connection.execute(`
      INSERT INTO ap_supplier_sites (
        site_id, supplier_id, site_name, site_type, address_line1, address_line2,
        city, state, postal_code, country, phone, email, contact_person,
        is_primary, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [siteId, req.params.supplierId, site_name, site_type, address_line1, address_line2,
        city, state, postal_code, country, phone, email, contact_person,
        is_primary ? 1 : 0, status]);
    
    console.log('✅ Site created successfully!');
    await connection.end();
    res.status(201).json({ 
      message: 'Supplier site created successfully',
      site_id: siteId
    });
  } catch (error) {
    console.error('❌ Error creating supplier site:', error);
    console.error('❌ Error stack:', error.stack);
    res.status(500).json({ error: 'Failed to create supplier site' });
  }
});

// Update supplier site
router.put('/suppliers/sites/:siteId', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    
    const {
      site_name, site_type, address_line1, address_line2, city, state,
      postal_code, country, phone, email, contact_person, is_primary, status
    } = req.body;

    // Normalize legacy/alias values to current ENUM values to avoid truncation
    const normalizedSiteType = (() => {
      if (!site_type) return null;
      const upper = String(site_type).toUpperCase();
      if (upper === 'BILL_TO') return 'INVOICING';
      if (upper === 'SHIP_TO') return 'PURCHASING';
      if (upper === 'PAYMENT') return 'INVOICING';
      if (['INVOICING', 'PURCHASING', 'BOTH'].includes(upper)) return upper;
      return null; // let DB reject if truly invalid
    })();
    
    // Get supplier_id for this site
    const [siteResult] = await connection.execute(
      'SELECT supplier_id FROM ap_supplier_sites WHERE site_id = ?',
      [req.params.siteId]
    );
    
    if (siteResult.length === 0) {
      await connection.end();
      return res.status(404).json({ error: 'Site not found' });
    }
    
    const supplierId = siteResult[0].supplier_id;
    
    // If this is primary, unset other primary sites
    if (is_primary) {
      await connection.execute(`
        UPDATE ap_supplier_sites 
        SET is_primary = 0 
        WHERE supplier_id = ? AND site_id != ?
      `, [supplierId, req.params.siteId]);
    }
    
    await connection.execute(`
      UPDATE ap_supplier_sites 
      SET site_name = ?, site_type = ?, address_line1 = ?, address_line2 = ?,
          city = ?, state = ?, postal_code = ?, country = ?, phone = ?, email = ?,
          contact_person = ?, is_primary = ?, status = ?
      WHERE site_id = ?
    `, [site_name, normalizedSiteType ?? site_type, address_line1, address_line2, city, state,
        postal_code, country, phone, email, contact_person, is_primary, status,
        req.params.siteId]);
    
    await connection.end();
    res.json({ message: 'Supplier site updated successfully' });
  } catch (error) {
    console.error('Error updating supplier site:', error);
    res.status(500).json({ error: 'Failed to update supplier site' });
  }
});

// Delete supplier site
router.delete('/suppliers/sites/:siteId', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    
    // Check if site exists
    const [siteResult] = await connection.execute(
      'SELECT site_id FROM ap_supplier_sites WHERE site_id = ?',
      [req.params.siteId]
    );
    
    if (siteResult.length === 0) {
      await connection.end();
      return res.status(404).json({ error: 'Site not found' });
    }
    
    // Delete the site
    await connection.execute('DELETE FROM ap_supplier_sites WHERE site_id = ?', [req.params.siteId]);
    
    await connection.end();
    res.json({ message: 'Supplier site deleted successfully' });
  } catch (error) {
    console.error('Error deleting supplier site:', error);
    res.status(500).json({ error: 'Failed to delete supplier site' });
  }
});

// ============================================================================
// SUPPLIER PROFILES MANAGEMENT
// ============================================================================

// Get all suppliers
router.get('/suppliers', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    
    const [rows] = await connection.execute(`
      SELECT 
        s.supplier_id,
        s.supplier_number,
        s.supplier_name,
        s.supplier_type,
        s.supplier_class,
        s.supplier_category,
        s.credit_limit,
        s.hold_flag,
        s.payment_terms_id,
        s.currency_code,
        s.payment_method,
        s.bank_account,
        s.tax_id,
        s.status,
        s.created_at,
        s.updated_at,
        p.party_id,
        p.party_number,
        p.party_name,
        p.party_type,
        p.tax_id as party_tax_id,
        p.website,
        p.industry
      FROM ap_suppliers s
      LEFT JOIN parties p ON s.party_id = p.party_id
      ORDER BY s.supplier_name
    `);
    
    await connection.end();
    res.json(rows);
  } catch (error) {
    console.error('Error fetching suppliers:', error);
    res.status(500).json({ error: 'Failed to fetch suppliers' });
  }
});

// Get supplier by ID
router.get('/suppliers/:id', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(`
      SELECT 
        s.supplier_id,
        s.supplier_number,
        s.party_id,
        s.supplier_name,
        s.supplier_type,
        s.supplier_class,
        s.supplier_category,
        s.credit_limit,
        s.hold_flag,
        s.payment_terms_id,
        s.currency_code,
        s.payment_method,
        s.bank_account,
        s.tax_id,
        s.status,
        s.created_by,
        s.created_at,
        s.updated_at,
        p.party_name,
        p.party_type,
        p.tax_id as party_tax_id,
        p.website,
        p.industry,
        p.party_number as party_no
      FROM ap_suppliers s
      LEFT JOIN parties p ON s.party_id = p.party_id
      WHERE s.supplier_id = ?
    `, [req.params.id]);
    
    await connection.end();
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Supplier not found' });
    }
    
    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching supplier:', error);
    res.status(500).json({ error: 'Failed to fetch supplier' });
  }
});

// Create supplier profile
router.post('/suppliers', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    
    // Get next supplier ID from sequence
    const supplierId = await getNextSequenceValue(connection, 'AP_SUPPLIER_ID_SEQ');
    
    // Generate supplier number
    const supplierNumber = `S${supplierId.toString().padStart(6, '0')}`;
    
    const {
      party_id, supplier_name, supplier_type, supplier_class, supplier_category,
      credit_limit, hold_flag, payment_terms_id, currency_code,
      payment_method, bank_account, tax_id, status
    } = req.body;
    
    console.log('🔍 Received supplier data:', req.body);
    console.log('🔍 Party ID:', party_id, 'Type:', typeof party_id);
    
    // Validate supplier_type
    const validSupplierTypes = ['VENDOR', 'CONTRACTOR', 'SERVICE_PROVIDER', 'GOVERNMENT'];
    if (!supplier_type || typeof supplier_type !== 'string' || supplier_type.trim() === '') {
      await connection.end();
      return res.status(400).json({ 
        error: 'Supplier type is required and must be one of: VENDOR, CONTRACTOR, SERVICE_PROVIDER, GOVERNMENT' 
      });
    }
    
    const normalizedSupplierType = supplier_type.trim().toUpperCase();
    if (!validSupplierTypes.includes(normalizedSupplierType)) {
      await connection.end();
      return res.status(400).json({ 
        error: `Invalid supplier type: "${supplier_type}". Must be one of: VENDOR, CONTRACTOR, SERVICE_PROVIDER, GOVERNMENT` 
      });
    }
    
    console.log('✅ Validated supplier_type:', normalizedSupplierType);
    
    // Get party information to extract tax_id
    console.log('🔍 Looking up party with ID:', party_id);
    const [partyResult] = await connection.execute(
      'SELECT tax_id FROM parties WHERE party_id = ?',
      [party_id]
    );
    
    console.log('🔍 Party lookup result:', partyResult);
    
    if (partyResult.length === 0) {
      console.log('❌ Party not found with ID:', party_id);
      await connection.end();
      return res.status(400).json({ error: 'Selected party not found' });
    }
    
    const party = partyResult[0];
    // Use tax_id from form data if provided and not empty, otherwise use party's tax_id
    const supplier_tax_id = req.body.tax_id && req.body.tax_id.trim() !== '' ? req.body.tax_id : party.tax_id;
    
    console.log('🔍 Party found:', party);
    console.log('🔍 Inserting supplier with party_id:', party_id);
    console.log('🔍 Supplier name from form:', supplier_name);
    console.log('🔍 Tax ID will be:', supplier_tax_id);
    
    console.log('🔍 About to execute INSERT with values:');
    console.log('🔍 supplierId:', supplierId);
    console.log('🔍 supplierNumber:', supplierNumber);
    console.log('🔍 party_id:', party_id);
    console.log('🔍 supplier_name:', supplier_name);
    console.log('🔍 supplier_type:', supplier_type);
    console.log('🔍 supplier_class:', supplier_class);
    console.log('🔍 supplier_category:', supplier_category);
    console.log('🔍 credit_limit:', credit_limit);
    console.log('🔍 hold_flag:', hold_flag);
    console.log('🔍 payment_terms_id:', payment_terms_id);
    console.log('🔍 currency_code:', currency_code);
    console.log('🔍 payment_method:', payment_method);
    console.log('🔍 bank_account:', bank_account);
    console.log('🔍 tax_id:', supplier_tax_id);
    console.log('🔍 status:', status);
    console.log('🔍 created_by:', 1);
    
    await connection.execute(`
      INSERT INTO ap_suppliers (
        supplier_id, supplier_number, party_id, supplier_name, supplier_type,
        supplier_class, supplier_category, credit_limit, hold_flag,
        payment_terms_id, currency_code, payment_method, bank_account,
        tax_id, status, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [supplierId, supplierNumber, party_id, supplier_name, normalizedSupplierType, supplier_class,
        supplier_category, credit_limit, hold_flag, payment_terms_id,
        currency_code, payment_method, bank_account, supplier_tax_id,
        status, 1]);
    
    await connection.end();
    res.status(201).json({ 
      message: 'Supplier created successfully',
      supplier_id: supplierId,
      supplier_number: supplierNumber
    });
  } catch (error) {
    console.error('Error creating supplier:', error);
    res.status(500).json({ error: 'Failed to create supplier' });
  }
});

// Update supplier profile
router.put('/suppliers/:id', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const {
      party_id, supplier_name, supplier_type, supplier_class, supplier_category, credit_limit,
      hold_flag, payment_terms_id, currency_code, payment_method,
      bank_account, status
    } = req.body;
    
    // Get party information to extract tax_id
    const [partyResult] = await connection.execute(
      'SELECT tax_id FROM parties WHERE party_id = ?',
      [party_id]
    );
    
    if (partyResult.length === 0) {
      await connection.end();
      return res.status(400).json({ error: 'Selected party not found' });
    }
    
    const party = partyResult[0];
    // Use tax_id from form data if provided and not empty, otherwise use party's tax_id
    const supplier_tax_id = req.body.tax_id && req.body.tax_id.trim() !== '' ? req.body.tax_id : party.tax_id;
    
    await connection.execute(`
      UPDATE ap_suppliers 
      SET party_id = ?, supplier_name = ?, supplier_type = ?, supplier_class = ?, supplier_category = ?,
          credit_limit = ?, hold_flag = ?, payment_terms_id = ?,
          currency_code = ?, payment_method = ?, bank_account = ?, tax_id = ?,
          status = ?
      WHERE supplier_id = ?
    `, [party_id, supplier_name, supplier_type, supplier_class, supplier_category, credit_limit,
        hold_flag, payment_terms_id, currency_code, payment_method,
        bank_account, supplier_tax_id, status, req.params.id]);
    
    await connection.end();
    res.json({ message: 'Supplier updated successfully' });
  } catch (error) {
    console.error('Error updating supplier:', error);
    res.status(500).json({ error: 'Failed to update supplier' });
  }
});

// Delete supplier profile
router.delete('/suppliers/:id', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    
    // Check if supplier exists
    const [supplierResult] = await connection.execute(
      'SELECT supplier_id FROM ap_suppliers WHERE supplier_id = ?',
      [req.params.id]
    );
    
    if (supplierResult.length === 0) {
      await connection.end();
      return res.status(404).json({ error: 'Supplier not found' });
    }
    
    // Delete the supplier
    await connection.execute('DELETE FROM ap_suppliers WHERE supplier_id = ?', [req.params.id]);
    
    await connection.end();
    res.json({ message: 'Supplier deleted successfully' });
  } catch (error) {
    console.error('Error deleting supplier:', error);
    res.status(500).json({ error: 'Failed to delete supplier' });
  }
});

// ============================================================================
// CONTACT POINTS MANAGEMENT
// ============================================================================

// Get party contact points
router.get('/parties/:partyId/contacts', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(
      'SELECT * FROM party_contact_points WHERE party_id = ? ORDER BY is_primary DESC, contact_point_type',
      [req.params.partyId]
    );
    
    await connection.end();
    res.json(rows);
  } catch (error) {
    console.error('Error fetching contact points:', error);
    res.status(500).json({ error: 'Failed to fetch contact points' });
  }
});

// Create contact point
router.post('/parties/:partyId/contacts', async (req, res) => {
  try {
    console.log('🔍 Creating contact point for party ID:', req.params.partyId);
    console.log('📦 Request body:', JSON.stringify(req.body, null, 2));
    
    const connection = await mysql.createConnection(dbConfig);
    
    // Get next contact point ID from sequence
    const contactPointId = await getNextSequenceValue(connection, 'HZ_CONTACT_POINT_ID_SEQ');
    console.log('🆔 Generated contact point ID:', contactPointId);
    
    const {
      contact_point_type, contact_point_value, contact_point_purpose,
      is_primary, status
    } = req.body;
    
    console.log('📋 Extracted data:', {
      contact_point_type, contact_point_value, contact_point_purpose,
      is_primary, status
    });
    
    // If this is primary, unset other primary contacts of the same type
    if (is_primary) {
      console.log('🔄 Unsetting other primary contacts of type:', contact_point_type);
      await connection.execute(`
        UPDATE hz_contact_points 
        SET is_primary = 0 
        WHERE party_id = ? AND contact_point_type = ?
      `, [req.params.partyId, contact_point_type]);
    }
    
    console.log('💾 Executing INSERT...');
    await connection.execute(`
      INSERT INTO party_contact_points (
        contact_point_id, party_id, contact_point_type, contact_point_value,
        contact_point_purpose, is_primary, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `, [contactPointId, req.params.partyId, contact_point_type,
        contact_point_value, contact_point_purpose, is_primary, status]);
    
    console.log('✅ Contact point created successfully!');
    await connection.end();
    res.status(201).json({ 
      message: 'Contact point created successfully',
      contact_point_id: contactPointId
    });
  } catch (error) {
    console.error('❌ Error creating contact point:', error);
    console.error('❌ Error stack:', error.stack);
    res.status(500).json({ error: 'Failed to create contact point' });
  }
});

// Update contact point
router.put('/contacts/:contactPointId', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    
    const {
      contact_point_type, contact_point_value, contact_point_purpose,
      is_primary, status
    } = req.body;
    
    // Get the party_id for this contact point
    const [contactResult] = await connection.execute(
      'SELECT party_id FROM party_contact_points WHERE contact_point_id = ?',
      [req.params.contactPointId]
    );
    
    if (contactResult.length === 0) {
      await connection.end();
      return res.status(404).json({ error: 'Contact point not found' });
    }
    
    const partyId = contactResult[0].party_id;
    
    // If this is primary, unset other primary contacts of the same type
    if (is_primary) {
      await connection.execute(`
        UPDATE hz_contact_points
        SET is_primary = 0 
        WHERE party_id = ? AND contact_point_type = ? AND contact_point_id != ?
      `, [partyId, contact_point_type, req.params.contactPointId]);
    }
    
    await connection.execute(`
      UPDATE party_contact_points SET
        contact_point_type = ?,
        contact_point_value = ?,
        contact_point_purpose = ?,
        is_primary = ?,
        status = ?,
        updated_at = NOW()
      WHERE contact_point_id = ?
    `, [contact_point_type, contact_point_value, contact_point_purpose,
        is_primary, status, req.params.contactPointId]);
    
    await connection.end();
    res.json({ message: 'Contact point updated successfully' });
  } catch (error) {
    console.error('Error updating contact point:', error);
    res.status(500).json({ error: 'Failed to update contact point' });
  }
});

// Delete contact point
router.delete('/contacts/:contactPointId', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    
    const [result] = await connection.execute(
      'DELETE FROM party_contact_points WHERE contact_point_id = ?',
      [req.params.contactPointId]
    );
    
    await connection.end();
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Contact point not found' });
    }
    
    res.json({ message: 'Contact point deleted successfully' });
  } catch (error) {
    console.error('Error deleting contact point:', error);
    res.status(500).json({ error: 'Failed to delete contact point' });
  }
});

// ============================================================================
// SEARCH AND FILTER
// ============================================================================

// Search parties
router.get('/search', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const { q, type, status } = req.query;
    
    let query = `
      SELECT 
        p.party_id,
        p.party_number,
        p.party_name,
        p.party_type,
        p.tax_id,
        p.website,
        p.industry,
        p.status,
        p.created_at
      FROM ap_parties p
      WHERE 1=1
    `;
    
    const params = [];
    
    if (q) {
      query += ` AND (p.party_name LIKE ? OR p.party_number LIKE ? OR p.tax_id LIKE ?)`;
      const searchTerm = `%${q}%`;
      params.push(searchTerm, searchTerm, searchTerm);
    }
    
    if (type && type !== 'ALL') {
      query += ` AND p.party_type = ?`;
      params.push(type);
    }
    
    if (status && status !== 'ALL') {
      query += ` AND p.status = ?`;
      params.push(status);
    }
    
    query += ` ORDER BY p.party_name LIMIT 50`;
    
    const [rows] = await connection.execute(query, params);
    await connection.end();
    res.json(rows);
  } catch (error) {
    console.error('Error searching parties:', error);
    res.status(500).json({ error: 'Failed to search parties' });
  }
});

export default router; 