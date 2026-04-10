import express from 'express';
import { executeQuery } from '../config/database.js';

const router = express.Router();

router.get('/', async (req, res) => {
  try {
    const customers = await executeQuery('SELECT id, name FROM customers');
    res.json(customers);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export default router; 