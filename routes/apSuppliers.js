import express from 'express';
import pool from '../config/database.js';
import APSequenceManager from '../utils/apSequenceManager.js';

const router = express.Router();

// Get all suppliers
router.get('/', async (req, res) => {
    try {
        const [rows] = await pool.execute(`
            SELECT s.*, 
                   COUNT(DISTINCT si.site_id) as site_count,
                   COUNT(DISTINCT i.invoice_id) as invoice_count,
                   SUM(CASE WHEN i.status != 'PAID' THEN i.amount_due ELSE 0 END) as outstanding_amount
            FROM ap_suppliers s
            LEFT JOIN ap_supplier_sites si ON s.supplier_id = si.supplier_id AND si.status = 'ACTIVE'
            LEFT JOIN ap_invoices i ON s.supplier_id = i.supplier_id AND i.status IN ('PENDING', 'APPROVED')
            GROUP BY s.supplier_id
            ORDER BY s.supplier_name
        `);
        
        res.json(rows);
    } catch (error) {
        console.error('Error fetching suppliers:', error);
        res.status(500).json({ error: 'Failed to fetch suppliers' });
    }
});

// Get supplier by ID
router.get('/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        const [supplierRows] = await pool.execute(`
            SELECT * FROM ap_suppliers WHERE supplier_id = ?
        `, [id]);
        
        if (supplierRows.length === 0) {
            return res.status(404).json({ error: 'Supplier not found' });
        }
        
        const [siteRows] = await pool.execute(`
            SELECT * FROM ap_supplier_sites 
            WHERE supplier_id = ? 
            ORDER BY is_primary DESC, site_name
        `, [id]);
        
        const supplier = supplierRows[0];
        supplier.sites = siteRows;
        
        res.json(supplier);
    } catch (error) {
        console.error('Error fetching supplier:', error);
        res.status(500).json({ error: 'Failed to fetch supplier' });
    }
});

// Create new supplier
router.post('/', async (req, res) => {
    try {
        const {
            supplier_name,
            supplier_type,
            tax_id,
            payment_terms_id,
            currency_code,
            credit_limit,
            hold_flag,
            status,
            sites
        } = req.body;

        // Validate required fields
        if (!supplier_name) {
            return res.status(400).json({ error: 'Supplier name is required' });
        }

        // Check if supplier name already exists
        const [existing] = await pool.execute(`
            SELECT supplier_id FROM ap_suppliers WHERE supplier_name = ?
        `, [supplier_name]);
        
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Supplier name already exists' });
        }

        // Start transaction
        await pool.execute('START TRANSACTION');

        try {
            // Generate supplier ID and number
            const supplierId = await APSequenceManager.getNextSupplierId();
            const supplierNumber = APSequenceManager.generateSupplierNumber(supplierId);

            // Insert supplier
            const [result] = await pool.execute(`
                INSERT INTO ap_suppliers (
                    supplier_id, supplier_number, supplier_name, supplier_type, tax_id,
                    payment_terms_id, currency_code, credit_limit, hold_flag, status, created_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `, [
                supplierId, supplierNumber, supplier_name, supplier_type || 'VENDOR',
                tax_id || null, payment_terms_id || 30, currency_code || 'USD',
                credit_limit || 0, hold_flag || false, status || 'ACTIVE', 1
            ]);

            // Create default invoicing site if no sites provided
            if (!sites || sites.length === 0) {
                const siteId = await APSequenceManager.getNextSupplierSiteId();
                await pool.execute(`
                    INSERT INTO ap_supplier_sites (
                        site_id, supplier_id, site_name, site_type, is_primary, status
                    ) VALUES (?, ?, ?, ?, ?, ?)
                `, [
                    siteId, supplierId,
                    `${supplier_name} - Invoicing Site`, 'INVOICING', true, 'ACTIVE'
                ]);
            } else {
                // Insert provided sites
                for (let i = 0; i < sites.length; i++) {
                    const site = sites[i];
                    const siteId = await APSequenceManager.getNextSupplierSiteId();
                    
                    await pool.execute(`
                        INSERT INTO ap_supplier_sites (
                            site_id, supplier_id, site_name, site_type, address_line1,
                            address_line2, city, state, postal_code, country, phone,
                            email, contact_person, payment_method, bank_account,
                            is_primary, status
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    `, [
                        siteId, supplierId, site.site_name,
                        (site.site_type && site.site_type.toUpperCase() === 'BILL_TO') ? 'INVOICING' :
                        (site.site_type && site.site_type.toUpperCase() === 'SHIP_TO') ? 'PURCHASING' :
                        (site.site_type && ['INVOICING','PURCHASING','BOTH'].includes(site.site_type.toUpperCase())) ? site.site_type.toUpperCase() : 'INVOICING',
                        site.address_line1 || null, site.address_line2 || null,
                        site.city || null, site.state || null, site.postal_code || null,
                        site.country || null, site.phone || null, site.email || null,
                        site.contact_person || null, site.payment_method || null,
                        site.bank_account || null, site.is_primary || (i === 0), 'ACTIVE'
                    ]);
                }
            }

            await pool.execute('COMMIT');

            // Fetch the created supplier with sites
            const [newSupplier] = await pool.execute(`
                SELECT * FROM ap_suppliers WHERE supplier_id = ?
            `, [supplierId]);

            const [sites] = await pool.execute(`
                SELECT * FROM ap_supplier_sites WHERE supplier_id = ?
            `, [supplierId]);

            const resultSupplier = newSupplier[0];
            resultSupplier.sites = sites;

            res.status(201).json(resultSupplier);
        } catch (error) {
            await pool.execute('ROLLBACK');
            throw error;
        }
    } catch (error) {
        console.error('Error creating supplier:', error);
        res.status(500).json({ error: 'Failed to create supplier' });
    }
});

// Update supplier
router.put('/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const {
            supplier_name,
            supplier_type,
            tax_id,
            payment_terms_id,
            currency_code,
            credit_limit,
            hold_flag,
            status
        } = req.body;

        // Check if supplier exists
        const [existing] = await pool.execute(`
            SELECT supplier_id FROM ap_suppliers WHERE supplier_id = ?
        `, [id]);
        
        if (existing.length === 0) {
            return res.status(404).json({ error: 'Supplier not found' });
        }

        // Check if supplier name already exists (excluding current supplier)
        if (supplier_name) {
            const [nameExists] = await pool.execute(`
                SELECT supplier_id FROM ap_suppliers 
                WHERE supplier_name = ? AND supplier_id != ?
            `, [supplier_name, id]);
            
            if (nameExists.length > 0) {
                return res.status(400).json({ error: 'Supplier name already exists' });
            }
        }

        // Update supplier
        await pool.execute(`
            UPDATE ap_suppliers SET
                supplier_name = COALESCE(?, supplier_name),
                supplier_type = COALESCE(?, supplier_type),
                tax_id = ?,
                payment_terms_id = COALESCE(?, payment_terms_id),
                currency_code = COALESCE(?, currency_code),
                credit_limit = COALESCE(?, credit_limit),
                hold_flag = COALESCE(?, hold_flag),
                status = COALESCE(?, status),
                updated_at = CURRENT_TIMESTAMP
            WHERE supplier_id = ?
        `, [
            supplier_name, supplier_type, tax_id, payment_terms_id,
            currency_code, credit_limit, hold_flag, status, id
        ]);

        // Fetch updated supplier
        const [updatedSupplier] = await pool.execute(`
            SELECT * FROM ap_suppliers WHERE supplier_id = ?
        `, [id]);

        res.json(updatedSupplier[0]);
    } catch (error) {
        console.error('Error updating supplier:', error);
        res.status(500).json({ error: 'Failed to update supplier' });
    }
});

// Delete supplier (soft delete by setting status to INACTIVE)
router.delete('/:id', async (req, res) => {
    try {
        const { id } = req.params;

        // Check if supplier has active invoices
        const [activeInvoices] = await pool.execute(`
            SELECT COUNT(*) as count FROM ap_invoices 
            WHERE supplier_id = ? AND status IN ('PENDING', 'APPROVED')
        `, [id]);

        if (activeInvoices[0].count > 0) {
            return res.status(400).json({ 
                error: 'Cannot delete supplier with active invoices' 
            });
        }

        // Soft delete supplier and all sites
        await pool.execute(`
            UPDATE ap_suppliers SET status = 'INACTIVE', updated_at = CURRENT_TIMESTAMP 
            WHERE supplier_id = ?
        `, [id]);

        await pool.execute(`
            UPDATE ap_supplier_sites SET status = 'INACTIVE', updated_at = CURRENT_TIMESTAMP 
            WHERE supplier_id = ?
        `, [id]);

        res.json({ message: 'Supplier deleted successfully' });
    } catch (error) {
        console.error('Error deleting supplier:', error);
        res.status(500).json({ error: 'Failed to delete supplier' });
    }
});

// Get supplier sites
router.get('/:id/sites', async (req, res) => {
    try {
        const { id } = req.params;
        
        const [rows] = await pool.execute(`
            SELECT * FROM ap_supplier_sites 
            WHERE supplier_id = ? 
            ORDER BY is_primary DESC, site_name
        `, [id]);
        
        res.json(rows);
    } catch (error) {
        console.error('Error fetching supplier sites:', error);
        res.status(500).json({ error: 'Failed to fetch supplier sites' });
    }
});

// Add supplier site
router.post('/:id/sites', async (req, res) => {
    try {
        const { id } = req.params;
        const siteData = req.body;

        // Check if supplier exists
        const [supplier] = await pool.execute(`
            SELECT supplier_id FROM ap_suppliers WHERE supplier_id = ?
        `, [id]);
        
        if (supplier.length === 0) {
            return res.status(404).json({ error: 'Supplier not found' });
        }

        const siteId = await APSequenceManager.getNextSupplierSiteId();
        
        await pool.execute(`
            INSERT INTO ap_supplier_sites (
                site_id, supplier_id, site_name, site_type, address_line1,
                address_line2, city, state, postal_code, country, phone,
                email, contact_person, payment_method, bank_account,
                is_primary, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            siteId, id, siteData.site_name, siteData.site_type || 'PAYMENT',
            siteData.address_line1 || null, siteData.address_line2 || null,
            siteData.city || null, siteData.state || null, siteData.postal_code || null,
            siteData.country || null, siteData.phone || null, siteData.email || null,
            siteData.contact_person || null, siteData.payment_method || null,
            siteData.bank_account || null, siteData.is_primary || false, 'ACTIVE'
        ]);

        const [newSite] = await pool.execute(`
            SELECT * FROM ap_supplier_sites WHERE site_id = ?
        `, [siteId]);

        res.status(201).json(newSite[0]);
    } catch (error) {
        console.error('Error creating supplier site:', error);
        res.status(500).json({ error: 'Failed to create supplier site' });
    }
});

export default router; 