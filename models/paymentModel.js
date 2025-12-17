const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
    name: String,
    price: Number,
    salePrice: Number, 
    originalPrice: Number,
});

const paymentSchema = new mongoose.Schema({
    ID: { type: Number, required: true, unique: true },
    transactionID: { type: String, required: true },
    paymentMethod: { type: String, required: true },
    userID: { type: String, required: true },
    username: { type: String, required: true },
    email: { type: String, required: true },
    products: [productSchema],
    discountCode: { type: String, default: null },
    discountPercentage: { type: Number, default: 0 },
    originalSubtotal: { type: Number, required: true },
    salesTaxAmount: { type: Number, required: true },
    discountAmount: { type: Number, required: true },
    totalPaid: { type: Number, required: true }, 
    createdAt: { type: Date, default: Date.now }
});


module.exports = mongoose.model('Payment', paymentSchema);
