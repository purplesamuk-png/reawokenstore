const mongoose = require('mongoose');

const reviewSchema = new mongoose.Schema({
  discordID: { type: String, required: true },
  discordUsername: { type: String },
  discordAvatarLocalPath: { type: String },
  productName: { type: String, required: true },
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  rating: { type: Number, required: true, min: 1, max: 5 },
  comment: { type: String, required: true, trim: true },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Review', reviewSchema);
