import express from 'express';
import { executeQuery } from '../config/database.js';
import pool from '../config/database.js';

const router = express.Router();

function safe(val) {
  return val === undefined ? null : val;
}

/**
 * Format date value to YYYY-MM-DD for MySQL DATE column
 * Handles Date objects, ISO strings, and date strings
 */
function formatDateForDB(dateValue) {
  if (!dateValue) {
    return null;
  }
  
  // If already in YYYY-MM-DD format, return as is
  if (typeof dateValue === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(dateValue)) {
    return dateValue;
  }
  
  // If it's a Date object, format it
  if (dateValue instanceof Date) {
    const year = dateValue.getFullYear();
    const month = String(dateValue.getMonth() + 1).padStart(2, '0');
    const day = String(dateValue.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  }
  
  // If it's an ISO string or date string, extract just the date part
  if (typeof dateValue === 'string') {
    // Extract YYYY-MM-DD from ISO string (e.g., "2025-12-19T19:00:00.000Z" -> "2025-12-19")
    const dateMatch = dateValue.match(/^(\d{4}-\d{2}-\d{2})/);
    if (dateMatch) {
      return dateMatch[1];
    }
    
    // Try parsing as Date
    try {
      const date = new Date(dateValue);
      if (!isNaN(date.getTime())) {
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
      }
    } catch (e) {
      console.warn('Failed to parse date:', dateValue, e);
      return null;
    }
  }
  
  return null;
}

/**
 * Update inventory item boxes based on quantity sold in AR invoice
 * Reduces inventory when items are sold
 * @param {number} invoiceId - The AR invoice ID
 * @param {boolean} isReversal - If true, add back inventory (for deletions/cancellations)
 */
async function updateInventoryFromARInvoice(invoiceId, isReversal = false) {
  try {
    // Get all invoice lines with item_code and quantity
    const [invoiceLines] = await pool.execute(
      `SELECT line_id, item_code, quantity 
       FROM ar_invoice_lines 
       WHERE invoice_id = ? AND item_code IS NOT NULL AND item_code != '' AND quantity > 0`,
      [invoiceId]
    );

    // OPTIMIZED: Batch fetch all inventory details in one query
    if (invoiceLines.length === 0) return;
    
    const itemCodes = invoiceLines.map(line => line.item_code).filter(Boolean);
    if (itemCodes.length === 0) return;
    
    const [allInventoryDetails] = await pool.execute(
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
    
    for (const line of invoiceLines) {
      const itemCode = line.item_code;
      const quantitySold = parseFloat(line.quantity) || 0;
      
      if (quantitySold <= 0 || !inventoryMap[itemCode]) {
        if (!inventoryMap[itemCode]) {
          console.warn(`Inventory item not found for item_code: ${itemCode}`);
        }
        continue;
      }

      const detail = inventoryMap[itemCode];
      let currentBoxQty = parseFloat(detail.box_quantity) || 0;
      let packetsPerBox = parseFloat(detail.packet_quantity) || 0;

      // packet_quantity represents "packets per box" (constant for the item)
      // If packet_quantity is 0, default to 1
      if (packetsPerBox <= 0) {
        packetsPerBox = 1;
        packetUpdates.push({ id: detail.id, itemCode });
      }

      // Calculate total units: boxes × packets per box
      const totalUnits = currentBoxQty * packetsPerBox;

      let newTotalUnits;
      if (isReversal) {
        // Add back inventory (for cancellations/deletions)
        newTotalUnits = totalUnits + quantitySold;
      } else {
        // Reduce inventory (for sales)
        newTotalUnits = Math.max(0, totalUnits - quantitySold);
      }

      // Calculate new boxes (packets per box remains constant)
      // Store boxes as decimal to preserve partial boxes
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
        quantitySold
      });
    }
    
    // Batch update packet_quantity for items that need it
    if (packetUpdates.length > 0) {
      await pool.execute(`
        UPDATE inventory_item_details 
        SET packet_quantity = 1, updated_at = CURRENT_TIMESTAMP
        WHERE id IN (${packetUpdates.map(() => '?').join(',')})
      `, packetUpdates.map(u => u.id));
      
      packetUpdates.forEach(u => {
        console.log(`Set default packets_per_box=1 for ${u.itemCode}`);
      });
    }
    
    // Batch update box_quantity for all items
    if (updates.length > 0) {
      await pool.execute(`
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
        console.log(`Updated inventory for ${u.itemCode}: ${u.currentBoxQty} boxes × ${u.packetsPerBox} packets/box (${u.totalUnits} units) → ${u.boxQty} boxes × ${u.packetsPerBox} packets/box (${calculatedTotal.toFixed(2)} calculated units, ${u.newTotalUnits} actual units) (${isReversal ? '+' : '-'}${u.quantitySold} units)`);
      });
    }
  } catch (error) {
    console.error('Error updating inventory from AR invoice:', error);
    throw error;
  }
}

// Helper function to get next sequence value
async function getNextSequenceValue(sequenceName) {
  await pool.query(
    'UPDATE ar_sequences SET current_value = current_value + increment_by WHERE sequence_name = ?',
    [sequenceName]
  );
  const [nextVal] = await pool.query(
    'SELECT current_value FROM ar_sequences WHERE sequence_name = ?',
    [sequenceName]
  );
  return nextVal[0].current_value;
}

// Create invoice
router.post('/', async (req, res) => {
  const {
    invoice_number, customer_id, customer_name, customer_site_id, invoice_date, due_date,
    payment_terms, currency_code, exchange_rate, notes, status, subtotal, tax_amount, total, line_items
  } = req.body;

  try {
    // Start transaction
    await pool.query('START TRANSACTION');

    // Validate and use customer_id if provided, otherwise fall back to lookup by name
    let customerId;
    let siteId;
    
    if (customer_id) {
      // Use provided customer_id and validate it exists
      const customerCheck = await executeQuery(
        'SELECT customer_id FROM ar_customers WHERE customer_id = ?',
        [customer_id]
      );
      
      if (customerCheck.length === 0) {
        await pool.query('ROLLBACK');
        return res.status(400).json({ error: `Customer with ID ${customer_id} not found` });
      }
      
      customerId = customer_id;
      
      // Use provided customer_site_id if available, otherwise find primary BILL_TO site
      if (customer_site_id) {
        // Validate that the site belongs to the customer
        const siteCheck = await executeQuery(
          'SELECT site_id FROM ar_customer_sites WHERE site_id = ? AND customer_id = ? AND status = "ACTIVE"',
          [customer_site_id, customerId]
        );
        
        if (siteCheck.length === 0) {
          await pool.query('ROLLBACK');
          return res.status(400).json({ error: `Site with ID ${customer_site_id} not found or does not belong to customer ${customerId}` });
        }
        
        siteId = customer_site_id;
      } else {
        // Fallback: Get primary bill-to site or any BILL_TO/BOTH site
        const site = await executeQuery(
          'SELECT site_id FROM ar_customer_sites WHERE customer_id = ? AND (site_type = "BILL_TO" OR site_type = "BOTH") AND status = "ACTIVE" ORDER BY is_primary DESC LIMIT 1',
          [customerId]
        );
        
        if (site.length === 0) {
          await pool.query('ROLLBACK');
          return res.status(400).json({ error: `No active billing site found for customer ${customerId}` });
        }
        
        siteId = site[0].site_id;
      }
    } else if (customer_name) {
      // Fallback: Look up customer by name (for backward compatibility)
      const existingCustomer = await executeQuery(
        'SELECT customer_id FROM ar_customers WHERE customer_name = ?',
        [customer_name]
      );

      if (existingCustomer.length > 0) {
        customerId = existingCustomer[0].customer_id;
        // Get primary bill-to site
        const site = await executeQuery(
          'SELECT site_id FROM ar_customer_sites WHERE customer_id = ? AND (site_type = "BILL_TO" OR site_type = "BOTH") AND status = "ACTIVE" ORDER BY is_primary DESC LIMIT 1',
          [customerId]
        );
        if (site.length > 0) {
          siteId = site[0].site_id;
        } else {
          await pool.query('ROLLBACK');
          return res.status(400).json({ error: `No active billing site found for customer ${customerId}` });
        }
      } else {
        await pool.query('ROLLBACK');
        return res.status(400).json({ error: `Customer "${customer_name}" not found. Please provide customer_id.` });
      }
    } else {
      await pool.query('ROLLBACK');
      return res.status(400).json({ error: 'Either customer_id or customer_name must be provided' });
    }

    // Create invoice
    const invoiceId = await getNextSequenceValue('AR_INVOICE_ID_SEQ');
    await executeQuery(
      `INSERT INTO ar_invoices
      (invoice_id, invoice_number, customer_id, bill_to_site_id, invoice_date, due_date, 
       payment_terms_id, currency_code, exchange_rate, subtotal, tax_amount, total_amount, status, notes, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        invoiceId, safe(invoice_number), customerId, siteId, formatDateForDB(invoice_date), formatDateForDB(due_date),
        safe(payment_terms), (currency_code !== undefined && currency_code !== null) ? currency_code : 'USD', 
        (exchange_rate !== undefined && exchange_rate !== null) ? exchange_rate : 1.0,
        safe(subtotal), safe(tax_amount), safe(total), 
        safe(status) || 'DRAFT', safe(notes), 1
      ]
    );

    // Create invoice lines
    if (line_items && Array.isArray(line_items)) {
      for (let i = 0; i < line_items.length; i++) {
        const line = line_items[i];
        const lineId = await getNextSequenceValue('AR_INVOICE_LINE_ID_SEQ');
        
        // Handle item_code: convert undefined/null/empty string to null, otherwise use the value
        const itemCode = (line.item_code && line.item_code.trim() !== '') ? line.item_code.trim() : null;
        
        await executeQuery(
          `INSERT INTO ar_invoice_lines
          (line_id, invoice_id, line_number, item_code, item_name, description, quantity, 
           unit_price, line_amount, tax_rate, tax_amount)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            lineId, invoiceId, safe(line.line_number) || (i + 1), itemCode,
            safe(line.item_name) || 'Item', safe(line.description),
            safe(line.quantity) || 1, safe(line.unit_price) || 0, safe(line.line_amount) || 0,
            safe(line.tax_rate) || 0, safe(line.tax_amount) || 0
          ]
        );
      }
    }

    // Update inventory based on sold quantities (reduce inventory)
    try {
      await updateInventoryFromARInvoice(invoiceId, false);
    } catch (inventoryError) {
      console.error('Failed to update inventory from AR invoice:', inventoryError);
      // Don't fail the request if inventory update fails, but log it
    }

    await pool.query('COMMIT');
    res.status(201).json({ message: 'Invoice created', invoice_id: invoiceId });
  } catch (err) {
    await pool.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  }
});

// Fetch invoice by ID
router.get('/:id', async (req, res) => {
  try {
    const invoiceRows = await executeQuery(`
      SELECT i.*, c.customer_name, c.customer_number, s.site_name, s.site_id as bill_to_site_id
      FROM ar_invoices i
      JOIN ar_customers c ON i.customer_id = c.customer_id
      JOIN ar_customer_sites s ON i.bill_to_site_id = s.site_id
      WHERE i.invoice_id = ?
    `, [req.params.id]);

    if (invoiceRows.length === 0) {
      return res.status(404).json({ error: 'Invoice not found' });
    }

    const invoice = invoiceRows[0];

    // Update status based on amount_due
    // If amount_due is 0 or less, status should be 'PAID'
    // If amount_due > 0 and status is PAID, status should be 'OPEN'
    // This ensures status always matches the actual payment state
    const amountDue = Number(invoice.amount_due) || 0;
    const currentStatus = invoice.status;
    
    if (currentStatus !== 'DRAFT' && currentStatus !== 'CANCELLED' && currentStatus !== 'VOID') {
      if (amountDue <= 0.01 && currentStatus !== 'PAID') {
        // Update status to PAID in database
        await pool.execute(`
          UPDATE ar_invoices 
          SET status = 'PAID', updated_at = CURRENT_TIMESTAMP
          WHERE invoice_id = ?
        `, [invoice.invoice_id]);
        invoice.status = 'PAID';
      } else if (amountDue > 0.01 && currentStatus === 'PAID') {
        // Update status to OPEN in database (partial payment scenario)
        await pool.execute(`
          UPDATE ar_invoices 
          SET status = 'OPEN', updated_at = CURRENT_TIMESTAMP
          WHERE invoice_id = ?
        `, [invoice.invoice_id]);
        invoice.status = 'OPEN';
      }
    }

    // Get invoice lines with calculated total_line_amount
    const lineRows = await executeQuery(
      `SELECT *, 
       (line_amount + tax_amount) as total_line_amount
       FROM ar_invoice_lines WHERE invoice_id = ? ORDER BY line_number`,
      [req.params.id]
    );

    invoice.line_items = lineRows;
    res.json(invoice);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Fetch all invoices
router.get('/', async (req, res) => {
  try {
    const startTime = Date.now();
    
    // Get all invoices with customer info
    const rows = await executeQuery(`
      SELECT i.*, c.customer_name, c.customer_number
      FROM ar_invoices i
      JOIN ar_customers c ON i.customer_id = c.customer_id
      ORDER BY i.invoice_id DESC
    `);

    if (rows.length === 0) {
      return res.json([]);
    }

    // Collect invoice IDs for batch operations
    const invoiceIds = rows.map(row => row.invoice_id);
    
    // OPTIMIZED: Fetch all line items in one query instead of N+1 queries
    const allLineItems = await executeQuery(`
      SELECT * FROM ar_invoice_lines 
      WHERE invoice_id IN (${invoiceIds.map(() => '?').join(',')})
      ORDER BY invoice_id, line_number
    `, invoiceIds);

    // Group line items by invoice_id
    const lineItemsMap = {};
    allLineItems.forEach(item => {
      if (!lineItemsMap[item.invoice_id]) {
        lineItemsMap[item.invoice_id] = [];
      }
      lineItemsMap[item.invoice_id].push(item);
    });

    // Prepare batch updates for status corrections
    const updatesToPaid = [];
    const updatesToOpen = [];

    // Process invoices and prepare updates
    const invoices = rows.map(row => {
      const amountDue = Number(row.amount_due) || 0;
      const currentStatus = row.status;
      
      // Only update status if it's not a terminal state (DRAFT, CANCELLED, VOID)
      // and the amount_due doesn't match the current status
      if (currentStatus !== 'DRAFT' && currentStatus !== 'CANCELLED' && currentStatus !== 'VOID') {
        if (amountDue <= 0.01 && currentStatus !== 'PAID') {
          updatesToPaid.push(row.invoice_id);
          row.status = 'PAID';
        } else if (amountDue > 0.01 && currentStatus === 'PAID') {
          updatesToOpen.push(row.invoice_id);
          row.status = 'OPEN';
        }
      }

      return {
        ...row,
        line_items: lineItemsMap[row.invoice_id] || []
      };
    });

    // OPTIMIZED: Batch update statuses instead of individual queries
    if (updatesToPaid.length > 0) {
      await pool.execute(`
        UPDATE ar_invoices 
        SET status = 'PAID', updated_at = CURRENT_TIMESTAMP
        WHERE invoice_id IN (${updatesToPaid.map(() => '?').join(',')})
      `, updatesToPaid);
    }

    if (updatesToOpen.length > 0) {
      await pool.execute(`
        UPDATE ar_invoices 
        SET status = 'OPEN', updated_at = CURRENT_TIMESTAMP
        WHERE invoice_id IN (${updatesToOpen.map(() => '?').join(',')})
      `, updatesToOpen);
    }

    const executionTime = Date.now() - startTime;
    if (executionTime > 1000) {
      console.warn(`⚠️ Slow invoices query: ${executionTime}ms for ${rows.length} invoices`);
    }

    res.json(invoices);
  } catch (err) {
    console.error('Error fetching invoices:', err);
    res.status(500).json({ error: err.message });
  }
});

// Update invoice
router.put('/:id', async (req, res) => {
  const {
    invoice_number, customer_id, customer_name, customer_site_id, invoice_date, due_date,
    payment_terms, currency_code, exchange_rate, notes, status, subtotal, tax_amount, total, line_items
  } = req.body;

  try {
    // Start transaction
    await pool.query('START TRANSACTION');

    // Validate customer_id and customer_site_id
    if (customer_id) {
      const customerCheck = await executeQuery(
        'SELECT customer_id FROM ar_customers WHERE customer_id = ?',
        [customer_id]
      );
      
      if (customerCheck.length === 0) {
        await pool.query('ROLLBACK');
        return res.status(400).json({ error: `Customer with ID ${customer_id} not found` });
      }
      
      if (customer_site_id) {
        const siteCheck = await executeQuery(
          'SELECT site_id FROM ar_customer_sites WHERE site_id = ? AND customer_id = ? AND status = "ACTIVE"',
          [customer_site_id, customer_id]
        );
        
        if (siteCheck.length === 0) {
          await pool.query('ROLLBACK');
          return res.status(400).json({ error: `Site with ID ${customer_site_id} not found or does not belong to customer ${customer_id}` });
        }
      }
    }

    // Update invoice header
    await executeQuery(
      `UPDATE ar_invoices SET
      invoice_number = ?, customer_id = ?, bill_to_site_id = ?, invoice_date = ?, due_date = ?, 
      payment_terms_id = ?, currency_code = ?, exchange_rate = ?, subtotal = ?, tax_amount = ?, total_amount = ?, status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
      WHERE invoice_id = ?`,
      [
        safe(invoice_number), customer_id ? parseInt(customer_id) : null, 
        customer_site_id ? parseInt(customer_site_id) : null,
        formatDateForDB(invoice_date), formatDateForDB(due_date),
        safe(payment_terms), (currency_code !== undefined && currency_code !== null) ? currency_code : 'USD',
        (exchange_rate !== undefined && exchange_rate !== null) ? exchange_rate : 1.0,
        safe(subtotal), safe(tax_amount), safe(total), 
        safe(status) || 'DRAFT', safe(notes), req.params.id
      ]
    );

    // Get old lines before deleting to reverse inventory
    const [oldLines] = await pool.execute(
      `SELECT item_code, quantity 
       FROM ar_invoice_lines 
       WHERE invoice_id = ? AND item_code IS NOT NULL AND item_code != '' AND quantity > 0`,
      [req.params.id]
    );
    
    // OPTIMIZED: Batch reverse old inventory (add back inventory by old sold quantities)
    if (oldLines.length > 0) {
      const oldItemCodes = oldLines.map(line => line.item_code).filter(Boolean);
      
      if (oldItemCodes.length > 0) {
        // Batch fetch all inventory details
        const [oldInventoryDetails] = await pool.execute(
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
          const oldQuantitySold = parseFloat(oldLine.quantity) || 0;
          
          if (oldQuantitySold <= 0 || !oldInventoryMap[itemCode]) continue;

          const detail = oldInventoryMap[itemCode];
          const currentBoxQty = parseFloat(detail.box_quantity) || 0;
          const currentPacketQty = parseFloat(detail.packet_quantity) || 0;
          const packetsPerBox = currentPacketQty > 0 ? currentPacketQty : 1;
          const totalUnits = currentBoxQty * packetsPerBox;

          const newTotalUnits = totalUnits + oldQuantitySold;
          const newBoxQty = Math.round((newTotalUnits / packetsPerBox) * 100) / 100;

          reverseUpdates.push({
            id: detail.id,
            boxQty: newBoxQty
          });
        }
        
        // Batch update all reversed inventory
        if (reverseUpdates.length > 0) {
          await pool.execute(`
            UPDATE inventory_item_details 
            SET box_quantity = CASE id
              ${reverseUpdates.map(() => 'WHEN ? THEN ?').join(' ')}
            END,
            updated_at = CURRENT_TIMESTAMP
            WHERE id IN (${reverseUpdates.map(() => '?').join(',')})
          `, [
            ...reverseUpdates.flatMap(u => [u.id, u.boxQty]),
            ...reverseUpdates.map(u => u.id)
          ]);
        }
      }
    }

    // Delete existing invoice lines
    await executeQuery(
      'DELETE FROM ar_invoice_lines WHERE invoice_id = ?',
      [req.params.id]
    );

    // Create new invoice lines
    if (line_items && Array.isArray(line_items)) {
      for (let i = 0; i < line_items.length; i++) {
        const line = line_items[i];
        const lineId = await getNextSequenceValue('AR_INVOICE_LINE_ID_SEQ');
        
        // Handle item_code: convert undefined/null/empty string to null, otherwise use the value
        const itemCode = (line.item_code && line.item_code.trim() !== '') ? line.item_code.trim() : null;
        
        await executeQuery(
          `INSERT INTO ar_invoice_lines
          (line_id, invoice_id, line_number, item_code, item_name, description, quantity, 
           unit_price, line_amount, tax_rate, tax_amount)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            lineId, req.params.id, safe(line.line_number) || (i + 1), itemCode,
            safe(line.item_name) || 'Item', safe(line.description),
            safe(line.quantity) || 1, safe(line.unit_price) || 0, safe(line.line_amount) || 0,
            safe(line.tax_rate) || 0, safe(line.tax_amount) || 0
          ]
        );
      }
    }

    // Update inventory based on new sold quantities (reduce inventory)
    try {
      await updateInventoryFromARInvoice(req.params.id, false);
    } catch (inventoryError) {
      console.error('Failed to update inventory from AR invoice update:', inventoryError);
      // Don't fail the request if inventory update fails, but log it
    }

    await pool.query('COMMIT');
    res.status(200).json({ message: 'Invoice updated', invoice_id: req.params.id });
  } catch (err) {
    await pool.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  }
});

// Update invoice status
router.patch('/:id/status', async (req, res) => {
  try {
    const { id } = req.params;
    const { status, approval_status } = req.body;

    console.log('Status update request:', { id, status, approval_status, body: req.body });

    // Check if invoice exists and get current status
    const [existing] = await pool.execute(
      'SELECT invoice_id, status, amount_due FROM ar_invoices WHERE invoice_id = ?',
      [id]
    );
    
    if (existing.length === 0) {
      return res.status(404).json({ error: 'Invoice not found' });
    }
    
    // Validate status values against ENUM
    // When approving, only update approval_status, not status
    const validStatuses = ['DRAFT', 'OPEN', 'PAID', 'CANCELLED', 'VOID'];
    const validApprovalStatuses = ['PENDING', 'APPROVED', 'REJECTED'];

    // Update status
    const updateFields = [];
    const params = [];

    if (status !== undefined && status !== null && status !== '') {
      const statusUpper = String(status).toUpperCase().trim();
      if (!validStatuses.includes(statusUpper)) {
        return res.status(400).json({ 
          error: `Invalid status value '${status}'. Must be one of: ${validStatuses.join(', ')}` 
        });
      }
      updateFields.push('status = ?');
      params.push(statusUpper);
    }

    if (approval_status !== undefined && approval_status !== null && approval_status !== '') {
      const approvalStatusUpper = String(approval_status).toUpperCase().trim();
      if (!validApprovalStatuses.includes(approvalStatusUpper)) {
        return res.status(400).json({ 
          error: `Invalid approval_status value '${approval_status}'. Must be one of: ${validApprovalStatuses.join(', ')}` 
        });
      }
      updateFields.push('approval_status = ?');
      params.push(approvalStatusUpper);
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'No status fields provided' });
    }

    updateFields.push('updated_at = CURRENT_TIMESTAMP');
    params.push(id);

    console.log('Executing update:', { updateFields, params });

    const oldStatus = existing[0].status;
    const newStatus = status ? String(status).toUpperCase().trim() : oldStatus;

    await pool.execute(
      `UPDATE ar_invoices SET ${updateFields.join(', ')} WHERE invoice_id = ?`,
      params
    );

    // Update inventory when invoice status changes
    // If invoice is cancelled/voided, restore inventory
    // If invoice changes from cancelled/voided to active, reduce inventory again
    if (status && newStatus !== oldStatus) {
      try {
        if ((newStatus === 'CANCELLED' || newStatus === 'VOID') && oldStatus !== 'CANCELLED' && oldStatus !== 'VOID') {
          // Invoice cancelled/voided: restore inventory
          await updateInventoryFromARInvoice(id, true);
        } else if ((oldStatus === 'CANCELLED' || oldStatus === 'VOID') && newStatus !== 'CANCELLED' && newStatus !== 'VOID') {
          // Invoice reactivated: reduce inventory again
          await updateInventoryFromARInvoice(id, false);
        }
      } catch (inventoryError) {
        console.error('Failed to update inventory from invoice status change:', inventoryError);
        // Don't fail the request if inventory update fails, but log it
      }
    }

    // Fetch updated invoice
    const [updatedInvoice] = await pool.execute(
      `SELECT invoice_id, invoice_number, customer_id, bill_to_site_id,
              invoice_date, due_date, payment_terms_id, currency_code,
              exchange_rate, subtotal, tax_amount, total_amount,
              amount_paid, amount_due, status, approval_status, notes,
              created_by, created_at, updated_at
       FROM ar_invoices WHERE invoice_id = ?`,
      [id]
    );

    res.json(updatedInvoice[0]);
  } catch (error) {
    console.error('Error updating invoice status:', error);
    console.error('Error details:', {
      message: error.message,
      sqlState: error.sqlState,
      sqlMessage: error.sqlMessage,
      code: error.code
    });
    
    // Provide more specific error messages
    if (error.code === 'WARN_DATA_TRUNCATED' || error.sqlState === '01000') {
      return res.status(400).json({ 
        error: 'Invalid status value. Valid statuses: DRAFT, OPEN, PAID, CANCELLED, VOID. Valid approval_statuses: PENDING, APPROVED, REJECTED',
        details: error.sqlMessage
      });
    }
    
    res.status(500).json({ 
      error: 'Failed to update invoice status',
      details: error.message 
    });
  }
});

export default router; 