import express from 'express';
import pool from '../config/database.js';

const router = express.Router();

// Get all inventory items
router.get('/', async (req, res) => {
  try {
    const [items] = await pool.execute(`
      SELECT 
        ih.id,
        ih.item_code,
        ih.item_name,
        ih.description,
        ih.category,
        ih.location,
        ih.brand,
        ih.supplier_id,
        ih.barcode,
        iid.item_purchase_rate,
        iid.item_sell_price,
        iid.tax_status,
        iid.box_quantity,
        iid.packet_quantity,
        iid.uom_type,
        iid.uom_type_detail,
        iid.income_account_segment_id,
        iid.cogs_account_segment_id,
        iid.inventory_account_segment_id,
        ih.created_at,
        ih.updated_at,
        s.supplier_name,
        s.supplier_number,
        COALESCE(SUM(bc.current_stock), 0) as quantity
      FROM inventory_items ih
      LEFT JOIN inventory_item_details iid 
        ON ih.id = iid.inventory_item_id 
       AND iid.is_active = 1
      LEFT JOIN ap_suppliers s ON ih.brand = s.supplier_id
      LEFT JOIN bin_cards bc ON ih.item_code = bc.item_code
      GROUP BY 
        ih.id, ih.item_code, ih.item_name, ih.description, ih.category, ih.location,
        ih.brand, ih.supplier_id, ih.barcode,
        iid.item_purchase_rate, iid.item_sell_price, iid.tax_status,
        iid.box_quantity, iid.packet_quantity, iid.uom_type, iid.uom_type_detail,
        iid.income_account_segment_id, iid.cogs_account_segment_id, iid.inventory_account_segment_id,
        ih.created_at, ih.updated_at, s.supplier_name, s.supplier_number
      ORDER BY ih.created_at DESC
    `);
    res.json({ success: true, data: items });
  } catch (error) {
    console.error('Error fetching inventory items:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Get single inventory item by id
router.get('/:id', async (req, res) => {
  try {
    const [items] = await pool.execute(`
      SELECT 
        ih.id,
        ih.item_code,
        ih.item_name,
        ih.description,
        ih.category,
        ih.location,
        ih.brand,
        ih.supplier_id,
        ih.barcode,
        iid.item_purchase_rate,
        iid.item_sell_price,
        iid.tax_status,
        iid.box_quantity,
        iid.packet_quantity,
        iid.uom_type,
        iid.uom_type_detail,
        iid.income_account_segment_id,
        iid.cogs_account_segment_id,
        iid.inventory_account_segment_id,
        iid.version,
        iid.inventory_account_segment_id,
        iid.version,
        iid.effective_start_date,
        iid.effective_end_date,
        iid.is_active,
        ih.created_at,
        ih.updated_at,
        s.supplier_name,
        s.supplier_number
      FROM inventory_items ih
      LEFT JOIN inventory_item_details iid 
        ON ih.id = iid.inventory_item_id 
       AND iid.is_active = 1
      LEFT JOIN ap_suppliers s ON ih.brand = s.supplier_id
      WHERE ih.id = ?
    `, [req.params.id]);
    if (items.length === 0) {
      return res.status(404).json({ success: false, message: 'Item not found' });
    }
    res.json({ success: true, data: items[0] });
  } catch (error) {
    console.error('Error fetching inventory item:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Create new inventory item
router.post('/', async (req, res) => {
  const connection = await pool.getConnection();
  try {
    console.log('Received request body:', JSON.stringify(req.body, null, 2));
    const {
      item_code, item_name, description, category, location,
      brand, supplier_id, barcode, item_purchase_rate, item_sell_price, tax_status,
      uom_type, box_quantity, packet_quantity, uom_type_detail,
      income_account_segment_id,
      cogs_account_segment_id,
      inventory_account_segment_id
    } = req.body;
    
    // Convert to proper types and handle null/undefined
    const packetQty = packet_quantity !== null && packet_quantity !== undefined 
      ? (typeof packet_quantity === 'string' ? parseFloat(packet_quantity) : packet_quantity) 
      : 0;
    const boxQty = box_quantity !== null && box_quantity !== undefined 
      ? (typeof box_quantity === 'string' ? parseFloat(box_quantity) : box_quantity) 
      : 0;
    
    console.log('Extracted packet_quantity (raw):', packet_quantity, 'Type:', typeof packet_quantity);
    console.log('Extracted packet_quantity (processed):', packetQty);
    console.log('Extracted box_quantity (processed):', boxQty);
    
    if (!item_code || !item_name) {
      return res.status(400).json({ success: false, message: 'Item code and name are required' });
    }

    await connection.beginTransaction();
    
    const [headerResult] = await connection.execute(
      `INSERT INTO inventory_items (
        item_code, item_name, description, category, location,
        brand, supplier_id, barcode
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        item_code,
        item_name,
        description,
        category,
        location,
        brand || (supplier_id ? supplier_id.toString() : null),
        supplier_id || null,
        barcode
      ]
    );

    const inventoryItemId = headerResult.insertId;

    await connection.execute(
      `INSERT INTO inventory_item_details (
        inventory_item_id,
        item_purchase_rate, item_sell_price, tax_status,
        uom_type, box_quantity, packet_quantity, uom_type_detail,
        income_account_segment_id, cogs_account_segment_id, inventory_account_segment_id,
        version, effective_start_date, effective_end_date, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURDATE(), NULL, 1)`,
      [
        inventoryItemId,
        parseFloat(item_purchase_rate) || 0,
        parseFloat(item_sell_price) || 0,
        tax_status || null,
        uom_type || null,
        boxQty,
        packetQty,
        parseFloat(uom_type_detail) || 0,
        income_account_segment_id || null,
        cogs_account_segment_id || null,
        inventory_account_segment_id || null,
        1
      ]
    );

    await connection.commit();
    res.status(201).json({ success: true, message: 'Inventory item created successfully', data: { id: inventoryItemId } });
  } catch (error) {
    await connection.rollback();
    console.error('Error creating inventory item:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  } finally {
    connection.release();
  }
});

// Update inventory item
router.put('/:id', async (req, res) => {
  const connection = await pool.getConnection();
  try {
    console.log('Update request body:', JSON.stringify(req.body, null, 2));
    const {
      item_code, item_name, description, category, location,
      brand, supplier_id, barcode, item_purchase_rate, item_sell_price, tax_status,
      uom_type, box_quantity, packet_quantity, uom_type_detail,
      income_account_segment_id,
      cogs_account_segment_id,
      inventory_account_segment_id
    } = req.body;
    
    // Convert to proper types and handle null/undefined
    const packetQty = packet_quantity !== null && packet_quantity !== undefined 
      ? (typeof packet_quantity === 'string' ? parseFloat(packet_quantity) : packet_quantity) 
      : 0;
    const boxQty = box_quantity !== null && box_quantity !== undefined 
      ? (typeof box_quantity === 'string' ? parseFloat(box_quantity) : box_quantity) 
      : 0;
    
    console.log('Update - packet_quantity (processed):', packetQty);
    
    if (!item_code || !item_name) {
      return res.status(400).json({ success: false, message: 'Item code and name are required' });
    }
    
    await connection.beginTransaction();

    const [headerResult] = await connection.execute(
      `UPDATE inventory_items SET 
        item_code = ?, item_name = ?, description = ?, category = ?, 
        location = ?, brand = ?, supplier_id = ?, barcode = ?,
        updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [
        item_code, item_name, description, category, location,
        brand || (supplier_id ? supplier_id.toString() : null),
        supplier_id || null,
        barcode,
        req.params.id
      ]
    );
    
    if (headerResult.affectedRows === 0) {
      await connection.rollback();
      return res.status(404).json({ success: false, message: 'Item not found' });
    }

    // Fetch current active detail row for comparison and locking
    const [currentDetails] = await connection.execute(
      `SELECT * FROM inventory_item_details 
       WHERE inventory_item_id = ? AND is_active = 1
       LIMIT 1 FOR UPDATE`,
      [req.params.id]
    );

    const currentDetail = currentDetails[0] || null;

    const incomingPurchaseRate = parseFloat(item_purchase_rate) || 0;
    const incomingSellPrice = parseFloat(item_sell_price) || 0;
    const incomingTaxStatus = tax_status || null;
    const incomingUomType = uom_type || null;
    const incomingBoxQty = boxQty;
    const incomingPacketQty = packetQty;
    const incomingUomDetail = parseFloat(uom_type_detail) || 0;
    const incomingIncomeSeg = income_account_segment_id || null;
    const incomingCogsSeg = cogs_account_segment_id || null;
    const incomingInvSeg = inventory_account_segment_id || null;

    const detailChanged =
      !currentDetail ||
      Number(currentDetail.item_purchase_rate || 0) !== incomingPurchaseRate ||
      Number(currentDetail.item_sell_price || 0) !== incomingSellPrice ||
      (currentDetail.tax_status || null) !== incomingTaxStatus ||
      (currentDetail.uom_type || null) !== incomingUomType ||
      Number(currentDetail.box_quantity || 0) !== Number(incomingBoxQty || 0) ||
      Number(currentDetail.packet_quantity || 0) !== Number(incomingPacketQty || 0) ||
      Number(currentDetail.uom_type_detail || 0) !== Number(incomingUomDetail || 0) ||
      (currentDetail.income_account_segment_id || null) !== incomingIncomeSeg ||
      (currentDetail.cogs_account_segment_id || null) !== incomingCogsSeg ||
      (currentDetail.inventory_account_segment_id || null) !== incomingInvSeg;

    const nextVersion = currentDetail ? Number(currentDetail.version || 1) + 1 : 1;

    if (detailChanged && currentDetail) {
      await connection.execute(
        `UPDATE inventory_item_details
         SET effective_end_date = CURDATE(),
             is_active = 0,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`,
        [currentDetail.id]
      );
    }

    if (detailChanged) {
      // Insert new active detail version
      await connection.execute(
        `INSERT INTO inventory_item_details (
          inventory_item_id,
          item_purchase_rate, item_sell_price, tax_status,
          uom_type, box_quantity, packet_quantity, uom_type_detail,
          income_account_segment_id, cogs_account_segment_id, inventory_account_segment_id, version,
          effective_start_date, effective_end_date, is_active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURDATE(), NULL, 1)`,
        [
          req.params.id,
          incomingPurchaseRate,
          incomingSellPrice,
          tax_status || null,
          uom_type || null,
          boxQty,
          packetQty,
          parseFloat(uom_type_detail) || 0,
          income_account_segment_id || null,
          cogs_account_segment_id || null,
          inventory_account_segment_id || null,
          nextVersion
        ]
      );
    } else {
      // Update current active detail without versioning
      await connection.execute(
        `UPDATE inventory_item_details SET 
          tax_status = ?,
          uom_type = ?, box_quantity = ?, packet_quantity = ?, uom_type_detail = ?,
          income_account_segment_id = ?, cogs_account_segment_id = ?, inventory_account_segment_id = ?,
          updated_at = CURRENT_TIMESTAMP
         WHERE inventory_item_id = ? AND is_active = 1`,
        [
          incomingTaxStatus,
          incomingUomType,
          incomingBoxQty,
          incomingPacketQty,
          incomingUomDetail,
          incomingIncomeSeg,
          incomingCogsSeg,
          incomingInvSeg,
          req.params.id
        ]
      );
    }
    
    await connection.commit();
    res.json({ success: true, message: 'Inventory item updated successfully' });
  } catch (error) {
    await connection.rollback();
    console.error('Error updating inventory item:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  } finally {
    connection.release();
  }
});

// Delete inventory item
router.delete('/:id', async (req, res) => {
  try {
    const [result] = await pool.execute('DELETE FROM inventory_items WHERE id = ?', [req.params.id]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Item not found' });
    }
    
    res.json({ success: true, message: 'Inventory item deleted successfully' });
  } catch (error) {
    console.error('Error deleting inventory item:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

export default router; 