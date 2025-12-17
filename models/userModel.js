const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  discordID: { type: String, required: true, unique: true },
  discordUsername: { type: String, unique: true },
  banned: { type: Boolean, required: true, default: false },
  email: { type: String, required: true },
  totalSpent: { type: Number, default: 0.0, required: true },
  joinedAt: { type: Date, default: Date.now },
  cart: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
  ownedProducts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
  ownedSerials: [{
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    productName: { type: String, required: true }, // Store name for quick access without population
    key: { type: String, required: true },
    purchaseDate: { type: Date, default: Date.now },
  }]
});

module.exports = mongoose.model('User', userSchema);
