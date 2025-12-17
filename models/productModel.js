const mongoose = require('mongoose');

const versionSchema = new mongoose.Schema({
    version: { type: String, required: true, trim: true },
    changelog: {  type: String,  required: true },
    productFile: { type: String, required: true },
    originalFileName: { type: String, required: true },
    releaseDate: { type: Date, default: Date.now },
    downloadCount: { type: Number, default: 0 }
});

const serialSchema = new mongoose.Schema({
    key: { type: String, required: true },
});

const productSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    description: { type: String, required: true, trim: true },
    price: { type: Number, required: true, min: 0 },
    productType: { type: String, enum: ['digitalPaid', 'digitalFree', 'service', 'serials'], required: true },
    serials: [serialSchema],
    serialRequiresFile: {
        type: Boolean,
        default: false
    },
    serviceMessage: { type: String, trim: true, default: '' },
    urlId: { type: String, required: true, unique: true, trim: true },
    position: { type: Number, required: true },
    bannerImage: { type: String, required: true },
    dependencies: { type: String, trim: true },
    createdAt: { type: Date, default: Date.now },
    discordRoleIds: { type: [String], default: [] },
    totalPurchases: { type: Number, default: 0, required: true },
    totalEarned: { type: Number, default: 0.0, required: true },
    totalDownloads: { type: Number, default: 0, required: true },
    category: { type: String, default: '' },
    hideProduct: { type: Boolean, default: false },
    pauseSelling: { type: Boolean, default: false },
    onSale: { type: Boolean, default: false },
    salePrice: { type: Number, default: null },
    saleStartDate: { type: Date, default: null },
    saleEndDate: { type: Date, default: null },
    versions: [versionSchema],
});

module.exports = mongoose.model('Product', productSchema);
