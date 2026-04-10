import pool from '../config/database.js';

/**
 * AP Sequence Manager
 * Manages sequences for the normalized Payables system following Oracle E-Business Suite R12 standards
 */
class APSequenceManager {
    
    /**
     * Get next sequence value for a given sequence name
     * @param {string} sequenceName - The name of the sequence
     * @returns {Promise<number>} - The next sequence value
     */
    static async getNextSequence(sequenceName) {
        // Get a connection from the pool for transaction
        const connection = await pool.getConnection();
        
        try {
            // Determine which sequences table to use based on the sequence name
            const tableName = sequenceName.startsWith('AP_') ? 'ap_sequences' : 'ar_sequences';
            
            // Start transaction using query (not execute)
            await connection.query('START TRANSACTION');
            
            // Update sequence value
            const [updateResult] = await connection.execute(`
                UPDATE ${tableName} 
                SET current_value = current_value + increment_by 
                WHERE sequence_name = ?
            `, [sequenceName]);
            
            if (updateResult.affectedRows === 0) {
                throw new Error(`Sequence '${sequenceName}' not found in ${tableName}`);
            }
            
            // Get the updated value
            const [rows] = await connection.execute(`
                SELECT current_value 
                FROM ${tableName} 
                WHERE sequence_name = ?
            `, [sequenceName]);
            
            // Commit transaction
            await connection.query('COMMIT');
            
            return rows[0].current_value;
        } catch (error) {
            // Rollback on error
            await connection.query('ROLLBACK');
            throw error;
        } finally {
            // Release connection back to pool
            connection.release();
        }
    }
    
    /**
     * Get next supplier ID
     * @returns {Promise<number>} - Next supplier ID
     */
    static async getNextSupplierId() {
        return await this.getNextSequence('AP_SUPPLIER_ID_SEQ');
    }
    
    /**
     * Get next supplier site ID
     * @returns {Promise<number>} - Next supplier site ID
     */
    static async getNextSupplierSiteId() {
        return await this.getNextSequence('AP_SUPPLIER_SITE_ID_SEQ');
    }
    
    /**
     * Get next invoice ID
     * @returns {Promise<number>} - Next invoice ID
     */
    static async getNextInvoiceId() {
        return await this.getNextSequence('AP_INVOICE_ID_SEQ');
    }
    
    /**
     * Get next invoice line ID
     * @returns {Promise<number>} - Next invoice line ID
     */
    static async getNextInvoiceLineId() {
        return await this.getNextSequence('AP_INVOICE_LINE_ID_SEQ');
    }
    
    /**
     * Get next payment ID
     * @returns {Promise<number>} - Next payment ID
     */
    static async getNextPaymentId() {
        return await this.getNextSequence('AP_PAYMENT_ID_SEQ');
    }
    
    /**
     * Get next payment application ID
     * @returns {Promise<number>} - Next payment application ID
     */
    static async getNextPaymentApplicationId() {
        return await this.getNextSequence('AP_PAYMENT_APPLICATION_ID_SEQ');
    }
    
    /**
     * Generate supplier number in Oracle E-Business Suite format
     * @param {number} supplierId - The supplier ID
     * @returns {string} - Formatted supplier number
     */
    static generateSupplierNumber(supplierId) {
        return `SUP${supplierId.toString().padStart(6, '0')}`;
    }
    
    /**
     * Generate invoice number in Oracle E-Business Suite format
     * @param {number} invoiceId - The invoice ID
     * @returns {string} - Formatted invoice number
     */
    static generateInvoiceNumber(invoiceId) {
        return `INV${invoiceId.toString().padStart(8, '0')}`;
    }
    
    /**
     * Generate payment number in Oracle E-Business Suite format
     * @param {number} paymentId - The payment ID
     * @returns {string} - Formatted payment number
     */
    static generatePaymentNumber(paymentId) {
        return `PAY${paymentId.toString().padStart(8, '0')}`;
    }
    
    /**
     * Reset sequence to a specific value
     * @param {string} sequenceName - The name of the sequence
     * @param {number} value - The value to reset to
     * @returns {Promise<void>}
     */
    static async resetSequence(sequenceName, value) {
        try {
            // Determine which sequences table to use
            const tableName = sequenceName.startsWith('AP_') ? 'ap_sequences' : 'ar_sequences';
            await pool.execute(`
                UPDATE ${tableName} 
                SET current_value = ? 
                WHERE sequence_name = ?
            `, [value, sequenceName]);
        } catch (error) {
            throw new Error(`Failed to reset sequence '${sequenceName}': ${error.message}`);
        }
    }
    
    /**
     * Get current sequence value without incrementing
     * @param {string} sequenceName - The name of the sequence
     * @returns {Promise<number>} - Current sequence value
     */
    static async getCurrentSequence(sequenceName) {
        try {
            // Determine which sequences table to use
            const tableName = sequenceName.startsWith('AP_') ? 'ap_sequences' : 'ar_sequences';
            const [rows] = await pool.execute(`
                SELECT current_value 
                FROM ${tableName} 
                WHERE sequence_name = ?
            `, [sequenceName]);
            
            if (rows.length === 0) {
                throw new Error(`Sequence '${sequenceName}' not found in ${tableName}`);
            }
            
            return rows[0].current_value;
        } catch (error) {
            throw new Error(`Failed to get current sequence '${sequenceName}': ${error.message}`);
        }
    }
    
    /**
     * Initialize sequences if they don't exist
     * @returns {Promise<void>}
     */
    static async initializeSequences() {
        try {
            const sequences = [
                'AP_SUPPLIER_ID_SEQ',
                'AP_SUPPLIER_SITE_ID_SEQ',
                'AP_INVOICE_ID_SEQ',
                'AP_INVOICE_LINE_ID_SEQ',
                'AP_PAYMENT_ID_SEQ',
                'AP_PAYMENT_APPLICATION_ID_SEQ'
            ];
            
            for (const seqName of sequences) {
                // Determine which sequences table to use
                const tableName = seqName.startsWith('AP_') ? 'ap_sequences' : 'ar_sequences';
                const [existing] = await pool.execute(`
                    SELECT COUNT(*) as count 
                    FROM ${tableName} 
                    WHERE sequence_name = ?
                `, [seqName]);
                
                if (existing[0].count === 0) {
                    await pool.execute(`
                        INSERT INTO ${tableName} (sequence_name, current_value) 
                        VALUES (?, 1)
                    `, [seqName]);
                }
            }
        } catch (error) {
            throw new Error(`Failed to initialize sequences: ${error.message}`);
        }
    }
    
    /**
     * Get sequence statistics
     * @returns {Promise<Object>} - Sequence statistics
     */
    static async getSequenceStats() {
        try {
            // Get stats from both tables
            const [apRows] = await pool.execute(`
                SELECT sequence_name, current_value, increment_by 
                FROM ap_sequences 
                WHERE sequence_name LIKE 'AP_%'
                ORDER BY sequence_name
            `);
            
            const [arRows] = await pool.execute(`
                SELECT sequence_name, current_value, increment_by 
                FROM ar_sequences 
                WHERE sequence_name LIKE 'AP_%'
                ORDER BY sequence_name
            `);
            
            // Combine results
            return [...apRows, ...arRows];
        } catch (error) {
            throw new Error(`Failed to get sequence stats: ${error.message}`);
        }
    }
}

export default APSequenceManager; 