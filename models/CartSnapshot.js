const mongoose = require('mongoose');

const CartSnapshotSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    items: [
        {
            productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
            price: { type: Number, required: true },
            salePrice: { type: Number },
            discountedPrice: { type: Number, required: true },
            quantity: { type: Number, default: 1 },
        }
    ],
    total: { type: Number, required: true },
    createdAt: { type: Date, default: Date.now, expires: '1h' },
});

module.exports = mongoose.model('CartSnapshot', CartSnapshotSchema);
