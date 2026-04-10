import express from 'express';
import pool from '../config/database.js';
import APSequenceManager from '../utils/apSequenceManager.js';

const router = express.Router();

// Get all invoices with supplier and site information
router.get('/', async (req, res) => {
    try {
        const { status, supplier_id, due_date_from, due_date_to } = req.query;
        
        let whereClause = 'WHERE 1=1';
        const params = [];
        
        if (status) {
            whereClause += ' AND i.status = ?';
            params.push(status);
        }
        
        if (supplier_id) {
            whereClause += ' AND i.supplier_id = ?';
            params.push(supplier_id);
        }
        
        if (due_date_from) {
            whereClause += ' AND i.due_date >= ?';
            params.push(due_date_from);
        }
        
        if (due_date_to) {
            whereClause += ' AND i.due_date <= ?';
            params.push(due_date_to);
        }
        
        const [rows] = await pool.execute(`
            SELECT 
                i.invoice_id, 
                i.invoice_number, 
                i.supplier_id, 
                i.receipt_id,
                i.bill_to_site_id,
                DATE_FORMAT(i.invoice_date, '%Y-%m-%d') as invoice_date, 
                DATE_FORMAT(i.due_date, '%Y-%m-%d') as due_date, 
                i.payment_terms_id, 
                i.currency_code,
                i.exchange_rate, 
                i.subtotal, 
                i.tax_amount, 
                i.total_amount,
                i.amount_paid, 
                i.amount_due, 
                i.status, 
                i.approval_status, 
                i.notes,
                i.created_by, 
                i.created_at, 
                i.updated_at,
                s.supplier_name, 
                s.supplier_number, 
                s.supplier_type,
                   si.site_name as bill_to_site_name,
                COALESCE(line_stats.line_count, 0) as line_count,
                COALESCE(line_stats.calculated_total, 0) as calculated_total
            FROM ap_invoices i
            LEFT JOIN ap_suppliers s ON i.supplier_id = s.supplier_id
            LEFT JOIN ap_supplier_sites si ON i.bill_to_site_id = si.site_id
            LEFT JOIN (
                SELECT 
                    invoice_id,
                    COUNT(line_id) as line_count,
                    SUM(total_line_amount) as calculated_total
                FROM ap_invoice_lines
                GROUP BY invoice_id
            ) line_stats ON i.invoice_id = line_stats.invoice_id
            ${whereClause}
            ORDER BY i.invoice_date DESC, i.invoice_id DESC
        `, params);
        
        // OPTIMIZED: Batch update status based on amount_due for each invoice
        // If amount_due is 0 or less, status should be 'PAID'
        // If amount_due > 0 and status is not DRAFT/PENDING/CANCELLED/VOID, status should be 'OPEN'
        // approval_status is managed manually by users, not automatically
        const updatesToPaid = [];
        const updatesToOpen = [];
        
        for (const row of rows) {
            const amountDue = Number(row.amount_due) || 0;
            const currentStatus = row.status;
            
            // Only update status if it's not a terminal state (DRAFT, PENDING, CANCELLED, VOID)
            // and the amount_due doesn't match the current status
            if (currentStatus !== 'DRAFT' && currentStatus !== 'PENDING' && 
                currentStatus !== 'CANCELLED' && currentStatus !== 'VOID') {
                if (amountDue <= 0.01 && currentStatus !== 'PAID') {
                    updatesToPaid.push(row.invoice_id);
                    row.status = 'PAID';
                } else if (amountDue > 0.01 && currentStatus === 'PAID') {
                    updatesToOpen.push(row.invoice_id);
                    row.status = 'OPEN';
                }
            }
        }
        
        // Batch update statuses instead of individual queries
        if (updatesToPaid.length > 0) {
            await pool.execute(`
                UPDATE ap_invoices 
                SET status = 'PAID', updated_at = CURRENT_TIMESTAMP
                WHERE invoice_id IN (${updatesToPaid.map(() => '?').join(',')})
            `, updatesToPaid);
        }
        
        if (updatesToOpen.length > 0) {
            await pool.execute(`
                UPDATE ap_invoices 
                SET status = 'OPEN', updated_at = CURRENT_TIMESTAMP
                WHERE invoice_id IN (${updatesToOpen.map(() => '?').join(',')})
            `, updatesToOpen);
        }
        
        res.json(rows);
    } catch (error) {
        console.error('Error fetching invoices:', error);
        console.error('Error details:', {
            message: error.message,
            sqlState: error.sqlState,
            sqlMessage: error.sqlMessage,
            code: error.code
        });
        res.status(500).json({ 
            error: 'Failed to fetch invoices',
            details: error.message 
        });
    }
});

// Get invoice line items (must come before /:id route)
router.get('/:id/lines', async (req, res) => {
    try {
        const { id } = req.params;
        
        const [rows] = await pool.execute(`
            SELECT * FROM ap_invoice_lines 
            WHERE invoice_id = ? 
            ORDER BY line_number
        `, [id]);
        
        res.json(rows);
    } catch (error) {
        console.error('Error fetching invoice lines:', error);
        res.status(500).json({ error: 'Failed to fetch invoice lines' });
    }
});

// Get invoice payment applications (must come before /:id route)
router.get('/:id/payments', async (req, res) => {
    try {
        const { id } = req.params;
        
        const [rows] = await pool.execute(`
            SELECT pa.*, p.payment_number, p.payment_date, p.payment_method
            FROM ap_payment_applications pa
            LEFT JOIN ap_payments p ON pa.payment_id = p.payment_id
            WHERE pa.invoice_id = ? AND pa.status = 'ACTIVE'
            ORDER BY pa.applied_date
        `, [id]);
        
        res.json(rows);
    } catch (error) {
        console.error('Error fetching invoice payments:', error);
        res.status(500).json({ error: 'Failed to fetch invoice payments' });
    }
});

// Get invoice by ID with line items (must come after specific routes)
router.get('/:id', async (req, res) => {
    try {
        const { id } = req.params;
        console.log('Fetching invoice by ID:', id);
        
        // Get invoice header - try bill_to_site_id first (actual database column), fallback to pay_to_site_id
        let invoiceRows;
        try {
            // Try with bill_to_site_id first (actual database column based on phpMyAdmin)
            [invoiceRows] = await pool.execute(`
                SELECT i.invoice_id, i.invoice_number, i.supplier_id, i.bill_to_site_id,
                       DATE_FORMAT(i.invoice_date, '%Y-%m-%d') as invoice_date, 
                       DATE_FORMAT(i.due_date, '%Y-%m-%d') as due_date, 
                       i.payment_terms_id, i.currency_code,
                       i.exchange_rate, i.subtotal, i.tax_amount, i.total_amount,
                       i.amount_paid, i.amount_due, i.status, i.approval_status, i.notes,
                       i.created_by, i.created_at, i.updated_at,
                       s.supplier_name, s.supplier_number, s.supplier_type,
                       si.site_name as bill_to_site_name, si.address_line1, si.city, si.state
                FROM ap_invoices i
                LEFT JOIN ap_suppliers s ON i.supplier_id = s.supplier_id
                LEFT JOIN ap_supplier_sites si ON i.bill_to_site_id = si.site_id
                WHERE i.invoice_id = ?
            `, [id]);
        } catch (colError) {
            console.error('Error with bill_to_site_id, trying pay_to_site_id:', colError.message);
            // If bill_to_site_id doesn't exist, try pay_to_site_id (schema definition)
            if (colError.code === 'ER_BAD_FIELD_ERROR' && (colError.message.includes('bill_to_site_id') || colError.message.includes('Unknown column'))) {
                [invoiceRows] = await pool.execute(`
            SELECT i.invoice_id, i.invoice_number, i.supplier_id, i.pay_to_site_id as bill_to_site_id,
                           DATE_FORMAT(i.invoice_date, '%Y-%m-%d') as invoice_date, 
                           DATE_FORMAT(i.due_date, '%Y-%m-%d') as due_date, 
                           i.payment_terms_id, i.currency_code,
                   i.exchange_rate, i.subtotal, i.tax_amount, i.total_amount,
                   i.amount_paid, i.amount_due, i.status, i.approval_status, i.notes,
                   i.created_by, i.created_at, i.updated_at,
                   s.supplier_name, s.supplier_number, s.supplier_type,
                   si.site_name as bill_to_site_name, si.address_line1, si.city, si.state
            FROM ap_invoices i
            LEFT JOIN ap_suppliers s ON i.supplier_id = s.supplier_id
            LEFT JOIN ap_supplier_sites si ON i.pay_to_site_id = si.site_id
            WHERE i.invoice_id = ?
        `, [id]);
            } else {
                throw colError;
            }
        }
        
        if (invoiceRows.length === 0) {
            return res.status(404).json({ error: 'Invoice not found' });
        }
        
        console.log('Invoice header fetched, getting line items and payments...');
        
        // Get line items
        let lineRows = [];
        try {
            [lineRows] = await pool.execute(`
            SELECT * FROM ap_invoice_lines 
            WHERE invoice_id = ? 
            ORDER BY line_number
        `, [id]);
            console.log('Line items fetched:', lineRows.length);
        } catch (lineError) {
            console.error('Error fetching line items:', lineError);
            // Continue without line items rather than failing completely
        }
        
        // Get payment applications
        let paymentRows = [];
        try {
            [paymentRows] = await pool.execute(`
                SELECT pa.*, p.payment_number, p.payment_date
                FROM ap_payment_applications pa
                LEFT JOIN ap_payments p ON pa.payment_id = p.payment_id
                WHERE pa.invoice_id = ? AND pa.status = 'ACTIVE'
                ORDER BY pa.created_at DESC
            `, [id]);
            console.log('Payment applications fetched:', paymentRows.length);
        } catch (paymentError) {
            console.error('Error fetching payment applications:', paymentError);
            // Try without ORDER BY if the error is about the column
            if (paymentError.code === 'ER_BAD_FIELD_ERROR') {
                try {
                    [paymentRows] = await pool.execute(`
            SELECT pa.*, p.payment_number, p.payment_date
            FROM ap_payment_applications pa
            LEFT JOIN ap_payments p ON pa.payment_id = p.payment_id
            WHERE pa.invoice_id = ? AND pa.status = 'ACTIVE'
        `, [id]);
                    console.log('Payment applications fetched (without ORDER BY):', paymentRows.length);
                } catch (retryError) {
                    console.error('Error fetching payment applications (retry):', retryError);
                }
            }
        }
        
        const invoice = invoiceRows[0];
        // Use 'lines' to match frontend expectation (APInvoiceForm expects 'lines')
        invoice.lines = lineRows || [];
        invoice.line_items = lineRows || []; // Also include line_items for backward compatibility
        invoice.payment_applications = paymentRows || [];
        
        // Update status based on amount_due
        const amountDue = Number(invoice.amount_due) || 0;
        const currentStatus = invoice.status;
        
        // Only update status if it's not a terminal state (DRAFT, PENDING, CANCELLED, VOID)
        // and the amount_due doesn't match the current status
        // approval_status is managed manually by users, not automatically
        if (currentStatus !== 'DRAFT' && currentStatus !== 'PENDING' && 
            currentStatus !== 'CANCELLED' && currentStatus !== 'VOID') {
            if (amountDue <= 0.01 && currentStatus !== 'PAID') {
                // Update status to PAID in database
                await pool.execute(`
                    UPDATE ap_invoices 
                    SET status = 'PAID', updated_at = CURRENT_TIMESTAMP
                    WHERE invoice_id = ?
                `, [invoice.invoice_id]);
                invoice.status = 'PAID';
            } else if (amountDue > 0.01 && currentStatus === 'PAID') {
                // Update status to OPEN in database
                await pool.execute(`
                    UPDATE ap_invoices 
                    SET status = 'OPEN', updated_at = CURRENT_TIMESTAMP
                    WHERE invoice_id = ?
                `, [invoice.invoice_id]);
                invoice.status = 'OPEN';
            }
        }
        
        console.log('Successfully fetched invoice:', invoice.invoice_id, invoice.invoice_number, 'with', lineRows.length, 'line items');
        res.json(invoice);
    } catch (error) {
        console.error('Error fetching invoice:', error);
        console.error('Error details:', {
            message: error.message,
            sqlState: error.sqlState,
            sqlMessage: error.sqlMessage,
            code: error.code,
            stack: error.stack
        });
        res.status(500).json({ 
            error: 'Failed to fetch invoice',
            details: error.message,
            code: error.code
        });
    }
});

// Create new invoice
router.post('/', async (req, res) => {
    try {
        const {
            supplier_id,
            pay_to_site_id,
            bill_to_site_id,
            receipt_id,
            invoice_number,
            invoice_date,
            due_date,
            payment_terms_id,
            currency_code,
            exchange_rate,
            subtotal,
            tax_amount,
            total_amount,
            notes,
            line_items
        } = req.body;

        // Use bill_to_site_id if provided, otherwise use pay_to_site_id (for backward compatibility)
        const site_id = bill_to_site_id || pay_to_site_id;

        // Validate required fields
        if (!supplier_id || !site_id || !invoice_date || !line_items || line_items.length === 0) {
            return res.status(400).json({ 
                error: 'Supplier ID, billing site ID, invoice date, and line items are required' 
            });
        }

        // Check if invoice number already exists
        if (invoice_number) {
            const [existing] = await pool.execute(`
                SELECT invoice_id FROM ap_invoices WHERE invoice_number = ?
            `, [invoice_number]);
            
            if (existing.length > 0) {
                return res.status(400).json({ error: 'Invoice number already exists' });
            }
        }

        // Get a connection from the pool for transaction
        const connection = await pool.getConnection();
        
        try {
            // Start transaction using query (not execute)
            await connection.query('START TRANSACTION');

            // Generate invoice ID and number
            const invoiceId = await APSequenceManager.getNextInvoiceId();
            const generatedInvoiceNumber = invoice_number || APSequenceManager.generateInvoiceNumber(invoiceId);

            // Calculate due date if not provided
            const calculatedDueDate = due_date || 
                new Date(new Date(invoice_date).getTime() + (payment_terms_id || 30) * 24 * 60 * 60 * 1000)
                .toISOString().split('T')[0];

            // Insert invoice header
            await connection.execute(`
                INSERT INTO ap_invoices (
                    invoice_id, invoice_number, supplier_id, receipt_id, bill_to_site_id,
                    invoice_date, due_date, payment_terms_id, currency_code,
                    exchange_rate, subtotal, tax_amount, total_amount, notes, created_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `, [
                invoiceId,
                generatedInvoiceNumber,
                supplier_id,
                receipt_id || null,
                site_id,
                invoice_date,
                calculatedDueDate,
                payment_terms_id || 30,
                currency_code || 'USD',
                exchange_rate || 1.0,
                subtotal || 0,
                tax_amount || 0,
                total_amount || 0,
                notes || null,
                1
            ]);

            // Insert line items
            for (let i = 0; i < line_items.length; i++) {
                const line = line_items[i];
                const lineId = await APSequenceManager.getNextInvoiceLineId();
                
                await connection.execute(`
                    INSERT INTO ap_invoice_lines (
                        line_id, invoice_id, line_number, item_code, item_name,
                        description, quantity, unit_price, line_amount,
                        tax_rate, tax_amount
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `, [
                    lineId, invoiceId, i + 1, line.item_code || null,
                    line.item_name, line.description || null, line.quantity || 1,
                    line.unit_price || 0, line.line_amount || 0,
                    line.tax_rate || 0, line.tax_amount || 0
                ]);
            }

            // Commit transaction
            await connection.query('COMMIT');

            // Fetch the created invoice with line items
            const [newInvoice] = await connection.execute(`
                SELECT invoice_id, invoice_number, supplier_id, receipt_id, bill_to_site_id,
                       invoice_date, due_date, payment_terms_id, currency_code,
                       exchange_rate, subtotal, tax_amount, total_amount,
                       amount_paid, amount_due, status, approval_status, notes,
                       created_by, created_at, updated_at
                FROM ap_invoices WHERE invoice_id = ?
            `, [invoiceId]);

            const [lines] = await connection.execute(`
                SELECT * FROM ap_invoice_lines WHERE invoice_id = ?
            `, [invoiceId]);

            const resultInvoice = newInvoice[0];
            resultInvoice.line_items = lines;

            res.status(201).json(resultInvoice);
        } catch (error) {
            // Rollback transaction
            await connection.query('ROLLBACK');
            throw error;
        } finally {
            // Release connection back to pool
            connection.release();
        }
    } catch (error) {
        console.error('Error creating invoice:', error);
        res.status(500).json({ error: 'Failed to create invoice' });
    }
});

// Update invoice
router.put('/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const {
            supplier_id,
            pay_to_site_id,
            bill_to_site_id,
            receipt_id,
            invoice_number,
            invoice_date,
            due_date,
            payment_terms_id,
            currency_code,
            exchange_rate,
            subtotal,
            tax_amount,
            total_amount,
            notes,
            line_items
        } = req.body;

        // Use bill_to_site_id if provided, otherwise use pay_to_site_id (for backward compatibility)
        const site_id = bill_to_site_id || pay_to_site_id;

        // Check if invoice exists
        const [existing] = await pool.execute(`
            SELECT invoice_id, status FROM ap_invoices WHERE invoice_id = ?
        `, [id]);
        
        if (existing.length === 0) {
            return res.status(404).json({ error: 'Invoice not found' });
        }

        // Don't allow updates to paid invoices
        if (existing[0].status === 'PAID') {
            return res.status(400).json({ error: 'Cannot update paid invoice' });
        }

        // Check if invoice number already exists (excluding current invoice)
        if (invoice_number) {
            const [nameExists] = await pool.execute(`
                SELECT invoice_id FROM ap_invoices 
                WHERE invoice_number = ? AND invoice_id != ?
            `, [invoice_number, id]);
            
            if (nameExists.length > 0) {
                return res.status(400).json({ error: 'Invoice number already exists' });
            }
        }

        // Get a connection from the pool for transaction
        const connection = await pool.getConnection();
        
        try {
            // Start transaction using query (not execute)
            await connection.query('START TRANSACTION');

            // Update invoice header
            await connection.execute(`
                UPDATE ap_invoices SET
                    supplier_id = COALESCE(?, supplier_id),
                    bill_to_site_id = COALESCE(?, bill_to_site_id),
                    receipt_id = COALESCE(?, receipt_id),
                    invoice_number = COALESCE(?, invoice_number),
                    invoice_date = COALESCE(?, invoice_date),
                    due_date = COALESCE(?, due_date),
                    payment_terms_id = COALESCE(?, payment_terms_id),
                    currency_code = COALESCE(?, currency_code),
                    exchange_rate = COALESCE(?, exchange_rate),
                    subtotal = COALESCE(?, subtotal),
                    tax_amount = COALESCE(?, tax_amount),
                    total_amount = COALESCE(?, total_amount),
                    notes = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE invoice_id = ?
            `, [
                supplier_id, site_id, receipt_id || null, invoice_number, invoice_date,
                due_date, payment_terms_id, currency_code, exchange_rate,
                subtotal, tax_amount, total_amount, notes, id
            ]);

            // Update line items if provided
            if (line_items && line_items.length > 0) {
                // Delete existing line items
                await connection.execute(`
                    DELETE FROM ap_invoice_lines WHERE invoice_id = ?
                `, [id]);

                // Insert new line items
                for (let i = 0; i < line_items.length; i++) {
                    const line = line_items[i];
                    const lineId = await APSequenceManager.getNextInvoiceLineId();
                    
                    await connection.execute(`
                        INSERT INTO ap_invoice_lines (
                            line_id, invoice_id, line_number, item_code, item_name,
                            description, quantity, unit_price, line_amount,
                            tax_rate, tax_amount
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    `, [
                        lineId, id, i + 1, line.item_code || null,
                        line.item_name, line.description || null, line.quantity || 1,
                        line.unit_price || 0, line.line_amount || 0,
                        line.tax_rate || 0, line.tax_amount || 0
                    ]);
                }
            }

            // Commit transaction
            await connection.query('COMMIT');

            // Fetch updated invoice
            const [updatedInvoice] = await connection.execute(`
                SELECT invoice_id, invoice_number, supplier_id, receipt_id, bill_to_site_id,
                       invoice_date, due_date, payment_terms_id, currency_code,
                       exchange_rate, subtotal, tax_amount, total_amount,
                       amount_paid, amount_due, status, approval_status, notes,
                       created_by, created_at, updated_at
                FROM ap_invoices WHERE invoice_id = ?
            `, [id]);

            const [lines] = await connection.execute(`
                SELECT * FROM ap_invoice_lines WHERE invoice_id = ?
            `, [id]);

            const resultInvoice = updatedInvoice[0];
            resultInvoice.line_items = lines;

            res.json(resultInvoice);
        } catch (error) {
            // Rollback transaction
            await connection.query('ROLLBACK');
            throw error;
        } finally {
            // Release connection back to pool
            connection.release();
        }
    } catch (error) {
        console.error('Error updating invoice:', error);
        res.status(500).json({ error: 'Failed to update invoice' });
    }
});

// Update invoice status
router.patch('/:id/status', async (req, res) => {
    try {
        const { id } = req.params;
        const { status, approval_status } = req.body;

        console.log('Status update request:', { id, status, approval_status, body: req.body });

        // Check if invoice exists and get current status
        const [existing] = await pool.execute(`
            SELECT invoice_id, status, amount_due FROM ap_invoices WHERE invoice_id = ?
        `, [id]);
        
        if (existing.length === 0) {
            return res.status(404).json({ error: 'Invoice not found' });
        }
        
        // Validate status values against ENUM
        // When approving, only update approval_status, not status
        const validStatuses = ['DRAFT', 'PENDING', 'OPEN', 'APPROVED', 'PAID', 'CANCELLED', 'VOID'];
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

        await pool.execute(`
            UPDATE ap_invoices SET ${updateFields.join(', ')} WHERE invoice_id = ?
        `, params);

        // Fetch updated invoice
        const [updatedInvoice] = await pool.execute(`
            SELECT invoice_id, invoice_number, supplier_id, bill_to_site_id,
                   invoice_date, due_date, payment_terms_id, currency_code,
                   exchange_rate, subtotal, tax_amount, total_amount,
                   amount_paid, amount_due, status, approval_status, notes,
                   created_by, created_at, updated_at
            FROM ap_invoices WHERE invoice_id = ?
        `, [id]);

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
                error: 'Invalid status value. Valid statuses: DRAFT, PENDING, APPROVED, PAID, CANCELLED, VOID. Valid approval_statuses: PENDING, APPROVED, REJECTED',
                details: error.sqlMessage
            });
        }
        
        res.status(500).json({ 
            error: 'Failed to update invoice status',
            details: error.message 
        });
    }
});

// Delete invoice (soft delete)
router.delete('/:id', async (req, res) => {
    try {
        const { id } = req.params;

        // Check if invoice has payments
        const [payments] = await pool.execute(`
            SELECT COUNT(*) as count FROM ap_payment_applications 
            WHERE invoice_id = ? AND status = 'ACTIVE'
        `, [id]);

        if (payments[0].count > 0) {
            return res.status(400).json({ 
                error: 'Cannot delete invoice with payment applications' 
            });
        }

        // Soft delete invoice and line items
        await pool.execute(`
            UPDATE ap_invoices SET status = 'CANCELLED', updated_at = CURRENT_TIMESTAMP 
            WHERE invoice_id = ?
        `, [id]);

        res.json({ message: 'Invoice deleted successfully' });
    } catch (error) {
        console.error('Error deleting invoice:', error);
        res.status(500).json({ error: 'Failed to delete invoice' });
    }
});

export default router; 