const mongoose = require('mongoose');

const DiscountCodeSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    discountPercentage: { type: Number, required: true, min: 0, max: 100 },
    maxUses: { type: Number, default: null, },
    uses: { type: Number, default: 0 },
    expiresAt: { type: Date, default: null }, createdAt: { type: Date, default: Date.now }
  });

module.exports = mongoose.model('DiscountCode', DiscountCodeSchema);
