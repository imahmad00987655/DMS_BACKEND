import express from 'express';
import pool from '../config/database.js';

const router = express.Router();

// Get all bin cards
router.get('/', async (req, res) => {
  try {
    const [cards] = await pool.execute('SELECT * FROM bin_cards ORDER BY created_at DESC');
    res.json({ success: true, data: cards });
  } catch (error) {
    console.error('Error fetching bin cards:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Get single bin card by id
router.get('/:id', async (req, res) => {
  try {
    const [cards] = await pool.execute('SELECT * FROM bin_cards WHERE id = ?', [req.params.id]);
    if (cards.length === 0) {
      return res.status(404).json({ success: false, message: 'Bin card not found' });
    }
    res.json({ success: true, data: cards[0] });
  } catch (error) {
    console.error('Error fetching bin card:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Create new bin card
router.post('/', async (req, res) => {
  try {
    const {
      item_code, item_name, bin_location, warehouse, unit_of_measure, current_stock,
      minimum_level, reorder_level, maximum_level, transaction_type, transaction_quantity,
      reference_number, notes
    } = req.body;
    if (!item_code || !item_name || !transaction_type) {
      return res.status(400).json({ success: false, message: 'Item code, name, and transaction type are required' });
    }
    await pool.execute(
      `INSERT INTO bin_cards (
        item_code, item_name, bin_location, warehouse, unit_of_measure, current_stock,
        minimum_level, reorder_level, maximum_level, transaction_type, transaction_quantity,
        reference_number, notes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [item_code, item_name, bin_location, warehouse, unit_of_measure, current_stock || 0,
        minimum_level || 0, reorder_level || 0, maximum_level || 0, transaction_type, transaction_quantity || 0,
        reference_number, notes]
    );
    res.status(201).json({ success: true, message: 'Bin card created successfully' });
  } catch (error) {
    console.error('Error creating bin card:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

export default router; 