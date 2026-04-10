import express from 'express';
import { authenticateToken } from '../middleware/auth.js';
import pool from '../config/database.js';

const router = express.Router();

// Get all journal entries
router.get('/', authenticateToken, async (req, res) => {
  try {
    const [entries] = await pool.execute(`
      SELECT 
        je.id,
        je.entry_id,
        je.entry_date,
        je.description,
        je.reference,
        je.status,
        je.total_debit,
        je.total_credit,
        je.created_at,
        je.updated_at,
        CONCAT(u.first_name, ' ', u.last_name) as created_by_name
      FROM journal_entries je
      LEFT JOIN users u ON je.created_by = u.id
      ORDER BY je.created_at DESC
    `);
    res.json({ success: true, data: entries });
  } catch (error) {
    console.error('Error fetching journal entries:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Get single journal entry with line items
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const entryId = req.params.id;
    const [entries] = await pool.execute(`
      SELECT 
        je.*,
        CONCAT(u.first_name, ' ', u.last_name) as created_by_name,
        CONCAT(p.first_name, ' ', p.last_name) as posted_by_name
      FROM journal_entries je
      LEFT JOIN users u ON je.created_by = u.id
      LEFT JOIN users p ON je.posted_by = p.id
      WHERE je.id = ?
    `, [entryId]);
    if (entries.length === 0) {
      return res.status(404).json({ success: false, message: 'Journal entry not found' });
    }
    const [lineItems] = await pool.execute(`
      SELECT 
        jeli.*,
        coa.account_code,
        coa.account_name,
        coa.account_type
      FROM journal_entry_line_items jeli
      JOIN chart_of_accounts coa ON jeli.account_id = coa.id
      WHERE jeli.journal_entry_id = ?
      ORDER BY jeli.line_order
    `, [entryId]);
    const entry = entries[0];
    entry.line_items = lineItems;
    res.json({ success: true, data: entry });
  } catch (error) {
    console.error('Error fetching journal entry:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Create new journal entry
router.post('/', authenticateToken, async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();
    const {
      entry_id,
      entry_date,
      description,
      reference,
      status,
      line_items
    } = req.body;
    const userId = req.user.id;
    if (!entry_id || !entry_date || !line_items || line_items.length < 1) {
      return res.status(400).json({ 
        success: false, 
        message: 'Entry ID, date, and at least 1 line item is required' 
      });
    }
    const totalDebit = line_items.reduce((sum, item) => sum + (parseFloat(item.debit_amount) || 0), 0);
    const totalCredit = line_items.reduce((sum, item) => sum + (parseFloat(item.credit_amount) || 0), 0);
    if (Math.abs(totalDebit - totalCredit) > 0.01) {
      return res.status(400).json({ 
        success: false, 
        message: 'Journal entry must balance (debits must equal credits)' 
      });
    }
    await conn.beginTransaction();
    try {
      const [result] = await conn.execute(`
        INSERT INTO journal_entries (
          entry_id, entry_date, description, reference, status, 
          total_debit, total_credit, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `, [entry_id, entry_date, description, reference, status, totalDebit, totalCredit, userId]);
      const journalEntryId = result.insertId;
      for (let i = 0; i < line_items.length; i++) {
        const item = line_items[i];
        await conn.execute(`
          INSERT INTO journal_entry_line_items (
            journal_entry_id, account_id, description, 
            debit_amount, credit_amount, line_order
          ) VALUES (?, ?, ?, ?, ?, ?)
        `, [
          journalEntryId,
          item.account_id,
          item.description,
          item.debit_amount || 0,
          item.credit_amount || 0,
          i + 1
        ]);
      }
      await conn.commit();
      res.status(201).json({ 
        success: true, 
        message: 'Journal entry created successfully',
        data: { id: journalEntryId, entry_id }
      });
    } catch (error) {
      await conn.rollback();
      throw error;
    }
  } catch (error) {
    console.error('Error creating journal entry:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  } finally {
    if (conn) conn.release();
  }
});

// Update journal entry
router.put('/:id', authenticateToken, async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();
    const entryId = req.params.id;
    const {
      entry_date,
      description,
      reference,
      status,
      line_items
    } = req.body;

    // Check if entry exists and is editable
    const [existing] = await conn.execute(`
      SELECT status FROM journal_entries WHERE id = ?
    `, [entryId]);

    if (existing.length === 0) {
      return res.status(404).json({ success: false, message: 'Journal entry not found' });
    }

    if (existing[0].status === 'posted') {
      return res.status(400).json({ success: false, message: 'Posted entries cannot be modified' });
    }

    // Require at least 1 line item
    if (!line_items || line_items.length < 1) {
      return res.status(400).json({
        success: false,
        message: 'At least 1 line item is required'
      });
    }

    // Calculate totals
    const totalDebit = line_items.reduce((sum, item) => sum + (parseFloat(item.debit_amount) || 0), 0);
    const totalCredit = line_items.reduce((sum, item) => sum + (parseFloat(item.credit_amount) || 0), 0);

    // Validate balance
    if (Math.abs(totalDebit - totalCredit) > 0.01) {
      return res.status(400).json({
        success: false,
        message: 'Journal entry must balance (debits must equal credits)'
      });
    }

    await conn.beginTransaction();
    try {
      // Update journal entry
      await conn.execute(`
        UPDATE journal_entries SET
          entry_date = ?, description = ?, reference = ?, status = ?,
          total_debit = ?, total_credit = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `, [entry_date, description, reference, status, totalDebit, totalCredit, entryId]);

      // Delete existing line items
      await conn.execute(`
        DELETE FROM journal_entry_line_items WHERE journal_entry_id = ?
      `, [entryId]);

      // Insert new line items
      for (let i = 0; i < line_items.length; i++) {
        const item = line_items[i];
        await conn.execute(`
          INSERT INTO journal_entry_line_items (
            journal_entry_id, account_id, description, 
            debit_amount, credit_amount, line_order
          ) VALUES (?, ?, ?, ?, ?, ?)
        `, [
          entryId,
          item.account_id,
          item.description,
          Number(item.debit_amount) || 0,
          Number(item.credit_amount) || 0,
          i + 1
        ]);
      }

      await conn.commit();
      res.json({ success: true, message: 'Journal entry updated successfully' });
    } catch (error) {
      await conn.rollback();
      throw error;
    }
  } catch (error) {
    console.error('Error updating journal entry:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  } finally {
    if (conn) conn.release();
  }
});

// Post journal entry
router.post('/:id/post', authenticateToken, async (req, res) => {
  try {
    const entryId = req.params.id;
    const userId = req.user.id;
    const [existing] = await pool.execute(`
      SELECT status, total_debit, total_credit FROM journal_entries WHERE id = ?
    `, [entryId]);
    if (existing.length === 0) {
      return res.status(404).json({ success: false, message: 'Journal entry not found' });
    }
    if (existing[0].status === 'posted') {
      return res.status(400).json({ success: false, message: 'Entry is already posted' });
    }
    if (existing[0].status === 'void') {
      return res.status(400).json({ success: false, message: 'Void entries cannot be posted' });
    }
    if (Math.abs(existing[0].total_debit - existing[0].total_credit) > 0.01) {
      return res.status(400).json({ 
        success: false, 
        message: 'Journal entry must balance before posting' 
      });
    }
    await pool.execute(`
      UPDATE journal_entries SET
        status = 'posted', posted_by = ?, posted_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `, [userId, entryId]);
    res.json({ success: true, message: 'Journal entry posted successfully' });
  } catch (error) {
    console.error('Error posting journal entry:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Get chart of accounts
router.get('/accounts/list', authenticateToken, async (req, res) => {
  try {
    const [accounts] = await pool.execute(`
      SELECT id, account_code, account_name, account_type
      FROM chart_of_accounts
      WHERE is_active = TRUE
      ORDER BY account_code
    `);
    res.json({ success: true, data: accounts });
  } catch (error) {
    console.error('Error fetching accounts:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Delete journal entry
router.delete('/:id', authenticateToken, async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();
    const entryId = req.params.id;
    await conn.beginTransaction();
    // Delete line items first (if not ON DELETE CASCADE)
    await conn.execute('DELETE FROM journal_entry_line_items WHERE journal_entry_id = ?', [entryId]);
    // Delete the journal entry
    const [result] = await conn.execute('DELETE FROM journal_entries WHERE id = ?', [entryId]);
    await conn.commit();
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Journal entry not found' });
    }
    res.json({ success: true, message: 'Journal entry deleted successfully' });
  } catch (error) {
    if (conn) await conn.rollback();
    console.error('Error deleting journal entry:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  } finally {
    if (conn) conn.release();
  }
});

export default router; 