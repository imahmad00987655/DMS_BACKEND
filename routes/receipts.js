import express from 'express';
import { executeQuery } from '../config/database.js';
import pool from '../config/database.js';

const router = express.Router();

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

// List all receipts
router.get('/', async (req, res) => {
  try {
    const receipts = await executeQuery(`
      SELECT r.*, c.customer_name, c.customer_number
      FROM ar_receipts r
      JOIN ar_customers c ON r.customer_id = c.customer_id
      ORDER BY r.receipt_id DESC
    `);
    res.json(receipts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get a single receipt by ID
router.get('/:id', async (req, res) => {
  try {
    const receiptRows = await executeQuery(`
      SELECT r.*, c.customer_name, c.customer_number
      FROM ar_receipts r
      JOIN ar_customers c ON r.customer_id = c.customer_id
      WHERE r.receipt_id = ?
    `, [req.params.id]);
    
    if (receiptRows.length === 0) {
      return res.status(404).json({ error: 'Receipt not found' });
    }
    
    const receipt = receiptRows[0];
    
    // Get receipt applications
    const applications = await executeQuery(`
      SELECT ra.*, i.invoice_number
      FROM ar_receipt_applications ra
      JOIN ar_invoices i ON ra.invoice_id = i.invoice_id
      WHERE ra.receipt_id = ? AND ra.status = 'ACTIVE'
    `, [req.params.id]);
    
    receipt.applications = applications;
    res.json(receipt);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

function safe(val) {
  return val === undefined ? null : val;
}

// Create a new receipt
router.post('/', async (req, res) => {
  const {
    receipt_number, receipt_date, customer_id, customer_name, amount_received,
    total_amount, currency, payment_method, bank_account, reference_number, 
    status, description, applications
  } = req.body;
  
  console.log('=== Receipt Creation Request ===');
  console.log('Request body keys:', Object.keys(req.body));
  console.log('Applications type:', typeof applications);
  console.log('Applications value:', applications);
  console.log('Is array?', Array.isArray(applications));
  
  // Get a connection from the pool for transaction
  const connection = await pool.getConnection();
  
  try {
    // Start transaction using query (not execute)
    await connection.query('START TRANSACTION');
    
    // Use total_amount if provided, otherwise use amount_received
    const receiptAmount = total_amount || amount_received;
    
    // Validate required fields
    if (!receipt_date || !receiptAmount) {
      await connection.query('ROLLBACK');
      connection.release();
      return res.status(400).json({ error: 'Receipt date and amount are required' });
    }
    
    // Check if receipt number already exists
    if (receipt_number) {
      const [existing] = await connection.execute(`
        SELECT receipt_id FROM ar_receipts WHERE receipt_number = ?
      `, [receipt_number]);
      
      if (existing.length > 0) {
        await connection.query('ROLLBACK');
        connection.release();
        return res.status(400).json({ error: 'Receipt number already exists' });
      }
    }
    
    // Get or validate customer
    let customerId;
    if (customer_id) {
      // Use provided customer_id and validate it exists
      const [customerCheck] = await connection.execute(
        'SELECT customer_id FROM ar_customers WHERE customer_id = ?',
        [customer_id]
      );
      
      if (customerCheck.length === 0) {
        await connection.query('ROLLBACK');
        connection.release();
        return res.status(400).json({ error: `Customer with ID ${customer_id} not found` });
      }
      
      customerId = customer_id;
    } else if (customer_name) {
      // Fallback: Look up customer by name (for backward compatibility)
      const [existingCustomer] = await connection.execute(
        'SELECT customer_id FROM ar_customers WHERE customer_name = ?',
        [customer_name]
      );

      if (existingCustomer.length > 0) {
        customerId = existingCustomer[0].customer_id;
      } else {
        await connection.query('ROLLBACK');
        connection.release();
        return res.status(400).json({ error: `Customer "${customer_name}" not found. Please provide customer_id.` });
      }
    } else {
      await connection.query('ROLLBACK');
      connection.release();
      return res.status(400).json({ error: 'Either customer_id or customer_name must be provided' });
    }
    
    // Determine receipt status - default to DRAFT if not explicitly set to PAID
    const receiptStatus = status === 'PAID' ? 'PAID' : 'DRAFT';
    
    // Create receipt
    const receiptId = await getNextSequenceValue('AR_RECEIPT_ID_SEQ');
    await connection.execute(
      `INSERT INTO ar_receipts
      (receipt_id, receipt_number, customer_id, receipt_date, currency_code, 
       total_amount, payment_method, bank_account, reference_number, status, notes, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        receiptId, safe(receipt_number), customerId, receipt_date, currency || 'USD',
        safe(receiptAmount), safe(payment_method), safe(bank_account), safe(reference_number), 
        receiptStatus, safe(description), 1
      ]
    );
    
    // Process applications if provided (like AP Payment)
    console.log('Receipt creation - applications received:', JSON.stringify(applications));
    
    if (applications && Array.isArray(applications) && applications.length > 0) {
      console.log(`Processing ${applications.length} application(s)`);
      let totalApplied = 0;
      
      for (const app of applications) {
        // Validate application data
        const invoiceId = app.invoice_id;
        const appliedAmount = app.application_amount || app.applied_amount;
        
        if (!invoiceId || appliedAmount === undefined || appliedAmount === null) {
          await pool.query('ROLLBACK');
          return res.status(400).json({ 
            error: `Invalid application data: invoice_id=${invoiceId}, application_amount=${appliedAmount}` 
          });
        }
        
        // Validate invoice exists and get invoice details to calculate unapplied amount
        const [invoiceRows] = await connection.execute(
          'SELECT invoice_id, total_amount, amount_paid, amount_due FROM ar_invoices WHERE invoice_id = ?',
          [invoiceId]
        );
        
        if (invoiceRows.length === 0) {
          await connection.query('ROLLBACK');
          connection.release();
          return res.status(400).json({ error: `Invoice with ID ${invoiceId} not found` });
        }
        
        const invoice = invoiceRows[0];
        // Calculate current amount due: total_amount - amount_paid (before this payment)
        // This ensures we get the correct value even if amount_due is NULL or a generated column
        const totalAmount = Number(invoice.total_amount) || 0;
        const currentAmountPaid = Number(invoice.amount_paid) || 0;
        const currentAmountDue = totalAmount - currentAmountPaid;
        const validAppliedAmount = Number(appliedAmount);
        
        if (validAppliedAmount <= 0) {
          await connection.query('ROLLBACK');
          connection.release();
          return res.status(400).json({ error: `Application amount must be greater than zero for invoice ${invoiceId}` });
        }
        
        if (validAppliedAmount > currentAmountDue) {
          await connection.query('ROLLBACK');
          connection.release();
          return res.status(400).json({ 
            error: `Application amount ${validAppliedAmount} exceeds invoice amount due ${currentAmountDue} for invoice ${invoiceId}` 
          });
        }
        
        // Calculate unapplied amount: remaining amount due on invoice after this application
        // This represents how much is still due on the invoice after applying this receipt amount
        // Formula: remaining amount due = (total_amount - current_amount_paid) - applied_amount
        const unappliedAmount = Math.max(0, currentAmountDue - validAppliedAmount);
        
        console.log('Unapplied amount calculation:', {
          invoiceId,
          totalAmount,
          currentAmountPaid,
          currentAmountDue,
          validAppliedAmount,
          unappliedAmount,
          remainingDue: currentAmountDue - validAppliedAmount
        });
        
        // Create receipt application
        const applicationId = await getNextSequenceValue('AR_RECEIPT_APPLICATION_ID_SEQ');
        console.log('Creating receipt application:', {
          applicationId,
          receiptId,
          invoiceId,
          appliedAmount: validAppliedAmount,
          unappliedAmount: unappliedAmount,
          appliedDate: app.application_date || receipt_date
        });
        
        try {
          const [insertResult] = await connection.execute(
            `INSERT INTO ar_receipt_applications
            (application_id, receipt_id, invoice_id, applied_amount, unapplied_amount, applied_date, status, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
              applicationId, receiptId, invoiceId, validAppliedAmount, unappliedAmount,
              app.application_date || receipt_date, 'ACTIVE', 1
            ]
          );
          console.log('Receipt application INSERT result:', insertResult);
          console.log('Receipt application created successfully:', applicationId);
        } catch (insertError) {
          console.error('Error inserting receipt application:', insertError);
          throw insertError;
        }
        
        totalApplied += validAppliedAmount;
        
        // Only update invoice balances for PAID receipts (not DRAFT)
        if (receiptStatus === 'PAID') {
          // Update invoice amount_paid and status
          // Status logic:
          // - If remaining amount due (after this payment) <= 0.01, status = 'PAID'
          // - Otherwise, status = 'OPEN' (partial payment or not fully paid)
          // This ensures that partial payments keep the invoice as OPEN, and only fully paid invoices are marked as PAID
          const newAmountPaid = currentAmountPaid + validAppliedAmount;
          const remainingAmountDue = totalAmount - newAmountPaid;
          const newStatus = remainingAmountDue <= 0.01 ? 'PAID' : 'OPEN';
          
          console.log('Updating invoice status (PAID receipt):', {
            invoiceId,
            currentAmountPaid,
            validAppliedAmount,
            newAmountPaid,
            totalAmount,
            remainingAmountDue,
            newStatus,
            calculation: `(${totalAmount} - (${currentAmountPaid} + ${validAppliedAmount})) = ${remainingAmountDue}`
          });
          
          await connection.execute(
            `UPDATE ar_invoices 
            SET amount_paid = amount_paid + ?,
                status = CASE 
                  WHEN (total_amount - (amount_paid + ?)) <= 0.01 THEN 'PAID'
                  ELSE 'OPEN'
                END,
                updated_at = CURRENT_TIMESTAMP
            WHERE invoice_id = ?`,
            [validAppliedAmount, validAppliedAmount, invoiceId]
          );
          
          // Verify the status was set correctly
          const [verifyInvoice] = await connection.execute(
            'SELECT invoice_id, total_amount, amount_paid, amount_due, status FROM ar_invoices WHERE invoice_id = ?',
            [invoiceId]
          );
          
          if (verifyInvoice.length > 0) {
            const verified = verifyInvoice[0];
            console.log('Invoice status after update:', {
              invoiceId,
              total_amount: verified.total_amount,
              amount_paid: verified.amount_paid,
              amount_due: verified.amount_due,
              status: verified.status,
              expectedStatus: newStatus
            });
            
            // If status doesn't match expected, force update it
            if (verified.status !== newStatus) {
              console.warn(`Status mismatch detected! Expected: ${newStatus}, Got: ${verified.status}. Forcing update...`);
              await connection.execute(
                'UPDATE ar_invoices SET status = ? WHERE invoice_id = ?',
                [newStatus, invoiceId]
              );
            }
          }
        } else {
          console.log('Receipt is DRAFT - skipping invoice updates');
        }
      }
      
      // Update receipt amount_applied (amount_unapplied is auto-calculated as GENERATED column)
      await connection.execute(
        'UPDATE ar_receipts SET amount_applied = ? WHERE receipt_id = ?',
        [totalApplied, receiptId]
      );
      
      console.log(`Updated receipt ${receiptId} with total_applied: ${totalApplied}`);
    } else {
      console.log('No applications provided or applications array is empty');
    }
    
    await connection.query('COMMIT');
    console.log(`Receipt ${receiptId} created successfully`);
    res.status(201).json({ message: 'Receipt created', receipt_id: receiptId });
  } catch (err) {
    console.error('Error creating receipt:', err);
    console.error('Error stack:', err.stack);
    await connection.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    // Always release the connection back to the pool
    connection.release();
  }
});

// Apply receipt to invoice
router.post('/:receiptId/apply', async (req, res) => {
  const { invoice_id, applied_amount } = req.body;
  
  try {
    // Validate receipt and invoice
    const receiptRows = await executeQuery(
      'SELECT total_amount, amount_applied FROM ar_receipts WHERE receipt_id = ?',
      [req.params.receiptId]
    );
    
    const invoiceRows = await executeQuery(
      'SELECT invoice_id, total_amount, amount_paid, amount_due FROM ar_invoices WHERE invoice_id = ?',
      [invoice_id]
    );
    
    if (receiptRows.length === 0) {
      return res.status(404).json({ error: 'Receipt not found' });
    }
    
    if (invoiceRows.length === 0) {
      return res.status(404).json({ error: 'Invoice not found' });
    }
    
    const receipt = receiptRows[0];
    const invoice = invoiceRows[0];
    
    // Calculate current amount due: total_amount - amount_paid (before this payment)
    // This ensures we get the correct value even if amount_due is NULL or a generated column
    const totalAmount = Number(invoice.total_amount) || 0;
    const currentAmountPaid = Number(invoice.amount_paid) || 0;
    const currentAmountDue = totalAmount - currentAmountPaid;
    
    // Validate application amount
    const availableAmount = receipt.total_amount - receipt.amount_applied;
    if (applied_amount > availableAmount) {
      return res.status(400).json({ error: 'Application amount exceeds available receipt amount' });
    }
    
    if (applied_amount > currentAmountDue) {
      return res.status(400).json({ error: 'Application amount exceeds invoice amount due' });
    }
    
    // Calculate unapplied amount: remaining amount due on invoice after this application
    // This represents how much is still due on the invoice after applying this receipt amount
    const unappliedAmount = Math.max(0, currentAmountDue - applied_amount);
    
    console.log('Apply receipt - unapplied amount calculation:', {
      invoice_id,
      totalAmount,
      currentAmountPaid,
      currentAmountDue,
      applied_amount,
      unappliedAmount,
      remainingDue: currentAmountDue - applied_amount
    });
    
    // Start transaction
    await pool.query('START TRANSACTION');
    
    try {
      // Create receipt application
      const applicationId = await getNextSequenceValue('AR_RECEIPT_APPLICATION_ID_SEQ');
      await executeQuery(
        `INSERT INTO ar_receipt_applications
        (application_id, receipt_id, invoice_id, applied_amount, unapplied_amount, applied_date, created_by)
        VALUES (?, ?, ?, ?, ?, CURRENT_DATE, ?)`,
        [applicationId, req.params.receiptId, invoice_id, applied_amount, unappliedAmount, 1]
      );
      
      // Update receipt amount_applied
      await executeQuery(
        'UPDATE ar_receipts SET amount_applied = amount_applied + ? WHERE receipt_id = ?',
        [applied_amount, req.params.receiptId]
      );
      
      // Update invoice amount_paid and status
      // Status logic: OPEN when partially paid, PAID when fully paid
      const newAmountPaid = currentAmountPaid + applied_amount;
      const remainingAmountDue = totalAmount - newAmountPaid;
      const newStatus = remainingAmountDue <= 0.01 ? 'PAID' : 'OPEN';
      
      console.log('Apply receipt - updating invoice status:', {
        invoice_id,
        currentAmountPaid,
        applied_amount,
        newAmountPaid,
        totalAmount,
        remainingAmountDue,
        newStatus,
        calculation: `(${totalAmount} - (${currentAmountPaid} + ${applied_amount})) = ${remainingAmountDue}`
      });
      
      await executeQuery(
        `UPDATE ar_invoices 
        SET amount_paid = amount_paid + ?,
            status = CASE 
              WHEN (total_amount - (amount_paid + ?)) <= 0.01 THEN 'PAID'
              ELSE 'OPEN'
            END,
            updated_at = CURRENT_TIMESTAMP
        WHERE invoice_id = ?`,
        [applied_amount, applied_amount, invoice_id]
      );
      
      // Verify the status was set correctly
      const [verifyInvoice] = await pool.execute(
        'SELECT invoice_id, total_amount, amount_paid, amount_due, status FROM ar_invoices WHERE invoice_id = ?',
        [invoice_id]
      );
      
      if (verifyInvoice.length > 0) {
        const verified = verifyInvoice[0];
        console.log('Invoice status after update (apply endpoint):', {
          invoice_id,
          total_amount: verified.total_amount,
          amount_paid: verified.amount_paid,
          amount_due: verified.amount_due,
          status: verified.status,
          expectedStatus: newStatus
        });
        
        // If status doesn't match expected, force update it
        if (verified.status !== newStatus) {
          console.warn(`Status mismatch detected! Expected: ${newStatus}, Got: ${verified.status}. Forcing update...`);
          await pool.execute(
            'UPDATE ar_invoices SET status = ? WHERE invoice_id = ?',
            [newStatus, invoice_id]
          );
        }
      }
      
      await pool.query('COMMIT');
      
      res.json({ message: 'Receipt applied successfully' });
    } catch (err) {
      await pool.query('ROLLBACK');
      throw err;
    }
  } catch (err) {
    console.error('Error applying receipt:', err);
    res.status(500).json({ error: err.message });
  }
});

// Update receipt
router.put('/:id', async (req, res) => {
  const connection = await pool.getConnection();
  
  try {
    const { id } = req.params;
    const {
      receipt_number, receipt_date, customer_id, total_amount,
      currency, payment_method, bank_account, reference_number,
      status, description, applications
    } = req.body;
    
    // Check if receipt exists
    const [existing] = await connection.execute(`
      SELECT receipt_id, status FROM ar_receipts WHERE receipt_id = ?
    `, [id]);
    
    if (existing.length === 0) {
      connection.release();
      return res.status(404).json({ error: 'Receipt not found' });
    }
    
    const currentStatus = existing[0].status;
    const targetStatus = status || currentStatus;
    
    // Don't allow updates to PAID receipts
    if (currentStatus === 'PAID') {
      connection.release();
      return res.status(400).json({ error: 'Cannot update paid receipt' });
    }
    
    // Check if receipt number already exists (excluding current receipt)
    if (receipt_number) {
      const [nameExists] = await connection.execute(`
        SELECT receipt_id FROM ar_receipts 
        WHERE receipt_number = ? AND receipt_id != ?
      `, [receipt_number, id]);
      
      if (nameExists.length > 0) {
        connection.release();
        return res.status(400).json({ error: 'Receipt number already exists' });
      }
    }
    
    // Start transaction
    await connection.query('START TRANSACTION');
    
    try {
      // If we're moving a DRAFT receipt to PAID and have applications,
      // we need to both update the header and apply the receipt to invoices
      if (currentStatus === 'DRAFT' && targetStatus === 'PAID' && applications && applications.length > 0) {
        // Update receipt header, including status
        await connection.execute(`
          UPDATE ar_receipts SET
            receipt_number = COALESCE(?, receipt_number),
            receipt_date = COALESCE(?, receipt_date),
            customer_id = COALESCE(?, customer_id),
            total_amount = COALESCE(?, total_amount),
            currency_code = COALESCE(?, currency_code),
            payment_method = ?,
            bank_account = ?,
            reference_number = ?,
            notes = ?,
            status = 'PAID',
            updated_at = CURRENT_TIMESTAMP
          WHERE receipt_id = ?
        `, [
          receipt_number, receipt_date, customer_id, total_amount,
          currency || 'USD', payment_method, bank_account, reference_number,
          description, id
        ]);
        
        // Remove any existing draft-stage applications so we can re-create them
        await connection.execute(`
          DELETE FROM ar_receipt_applications
          WHERE receipt_id = ?
        `, [id]);
        
        let totalApplied = 0;
        
        for (const app of applications) {
          const invoiceId = Number(app.invoice_id);
          const appliedAmount = Number(app.application_amount);
          const appliedDate = app.application_date || receipt_date || new Date().toISOString().split('T')[0];
          
          if (!invoiceId || !appliedAmount || appliedAmount <= 0) {
            throw new Error(`Invalid application data: invoice_id=${invoiceId}, application_amount=${appliedAmount}`);
          }
          
          // Get invoice details
          const [invoiceDetails] = await connection.execute(`
            SELECT total_amount, amount_paid, amount_due 
            FROM ar_invoices 
            WHERE invoice_id = ?
          `, [invoiceId]);
          
          if (invoiceDetails.length === 0) {
            throw new Error(`Invoice ${invoiceId} not found`);
          }
          
          const totalAmount = Number(invoiceDetails[0].total_amount) || 0;
          const currentAmountPaid = Number(invoiceDetails[0].amount_paid) || 0;
          const currentAmountDue = totalAmount - currentAmountPaid;
          
          if (appliedAmount > currentAmountDue) {
            throw new Error(`Application amount ${appliedAmount} exceeds invoice amount due ${currentAmountDue}`);
          }
          
          // Calculate unapplied amount
          const unappliedAmount = Math.max(0, currentAmountDue - appliedAmount);
          
          // Create receipt application
          const applicationId = await getNextSequenceValue('AR_RECEIPT_APPLICATION_ID_SEQ');
          await connection.execute(`
            INSERT INTO ar_receipt_applications
            (application_id, receipt_id, invoice_id, applied_amount, unapplied_amount, applied_date, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
          `, [applicationId, id, invoiceId, appliedAmount, unappliedAmount, appliedDate, 1]);
          
          // Update invoice amount_paid and status
          const newAmountPaid = currentAmountPaid + appliedAmount;
          const remainingAmountDue = totalAmount - newAmountPaid;
          const newStatus = remainingAmountDue <= 0.01 ? 'PAID' : 'OPEN';
          
          await connection.execute(`
            UPDATE ar_invoices 
            SET amount_paid = amount_paid + ?,
                status = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE invoice_id = ?
          `, [appliedAmount, newStatus, invoiceId]);
          
          totalApplied += appliedAmount;
        }
        
        // Update receipt amount_applied
        await connection.execute(`
          UPDATE ar_receipts 
          SET amount_applied = ?, updated_at = CURRENT_TIMESTAMP
          WHERE receipt_id = ?
        `, [totalApplied, id]);
        
      } else {
        // Simple header-only update (no invoice / applications logic)
        await connection.execute(`
          UPDATE ar_receipts SET
            receipt_number = COALESCE(?, receipt_number),
            receipt_date = COALESCE(?, receipt_date),
            customer_id = COALESCE(?, customer_id),
            total_amount = COALESCE(?, total_amount),
            currency_code = COALESCE(?, currency_code),
            payment_method = ?,
            bank_account = ?,
            reference_number = ?,
            notes = ?,
            updated_at = CURRENT_TIMESTAMP
          WHERE receipt_id = ?
        `, [
          receipt_number, receipt_date, customer_id, total_amount,
          currency || 'USD', payment_method, bank_account, reference_number,
          description, id
        ]);
      }
      
      await connection.query('COMMIT');
      
      // Fetch updated receipt with applications
      const [updatedReceipt] = await connection.execute(`
        SELECT r.*, c.customer_name, c.customer_number
        FROM ar_receipts r
        JOIN ar_customers c ON r.customer_id = c.customer_id
        WHERE r.receipt_id = ?
      `, [id]);
      
      // Get receipt applications
      const [receiptApplications] = await connection.execute(`
        SELECT ra.*, i.invoice_number
        FROM ar_receipt_applications ra
        JOIN ar_invoices i ON ra.invoice_id = i.invoice_id
        WHERE ra.receipt_id = ? AND ra.status = 'ACTIVE'
      `, [id]);
      
      const receipt = updatedReceipt[0];
      receipt.applications = receiptApplications;
      
      connection.release();
      res.json(receipt);
    } catch (error) {
      await connection.query('ROLLBACK');
      connection.release();
      throw error;
    }
  } catch (error) {
    console.error('Error updating receipt:', error);
    if (connection) {
      connection.release();
    }
    res.status(500).json({ error: error.message || 'Failed to update receipt' });
  }
});

// Check if invoices are already in draft receipts
router.post('/check-draft-conflicts', async (req, res) => {
  try {
    const { invoice_ids, exclude_receipt_id } = req.body;
    
    if (!invoice_ids || !Array.isArray(invoice_ids) || invoice_ids.length === 0) {
      return res.json([]);
    }
    
    // Build query to find draft receipts containing these invoices
    let query = `
      SELECT DISTINCT
        ra.invoice_id,
        i.invoice_number,
        r.receipt_id,
        r.receipt_number
      FROM ar_receipt_applications ra
      INNER JOIN ar_receipts r ON ra.receipt_id = r.receipt_id
      INNER JOIN ar_invoices i ON ra.invoice_id = i.invoice_id
      WHERE r.status = 'DRAFT'
        AND ra.invoice_id IN (${invoice_ids.map(() => '?').join(',')})
    `;
    
    const params = [...invoice_ids];
    
    // Exclude a specific receipt (useful when editing a draft receipt)
    if (exclude_receipt_id) {
      query += ' AND r.receipt_id != ?';
      params.push(exclude_receipt_id);
    }
    
    const [rows] = await pool.execute(query, params);
    
    res.json(rows);
  } catch (error) {
    console.error('Error checking draft receipt conflicts:', error);
    res.status(500).json({ error: 'Failed to check draft receipt conflicts' });
  }
});

export default router; 