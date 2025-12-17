const mongoose = require('mongoose');

const categorySchema = new mongoose.Schema({
  name: { type: String, required: true },
  url: { type: String, required: true },
});

const settingsSchema = new mongoose.Schema({
  termsOfService: { type: String, required: true, default: 'Your terms of service go here...' },
  privacyPolicy: { 
    type: String, 
    required: true, 
    default: `
## Privacy Policy

We value your privacy and are committed to safeguarding the personal information you share with us. This Privacy Policy explains how we collect, use, and protect your data when you interact with our website and services.

---

### Types of Personal Information Collected and Stored

1.1. We collect the following personal information when you use third-party login services or create an account on our website:
- Account ID (from third-party login services such as Discord, GitHub, Google, etc.)
- Email address
- User profile information (such as profile picture/avatar, guilds, etc.)
- Internet Protocol (IP) address
- Payment details (For PayPal, we collect your account handle/email; for Stripe, we collect the last 4 digits of your card and transaction details; for Coinbase, we collect transaction details, including the payment method used, the transaction amount, and the cryptocurrency involved.)

1.2. We use login services through platforms such as Discord, GitHub, Google, and Twitter. These platforms provide basic information via their respective APIs. Please refer to their privacy policies for further details on how they handle your data.

---

### Information Collection Process

2.1. When you log in and create an account, your personal information is securely collected and stored in our database. Payment information is only collected when a purchase is made on our website.

---

### Use of Your Information

3.1. We use the information we collect for the following purposes:
- Managing your account and providing related services
- Maintaining administrative records, including payment history and receipts
- Collecting aggregated data for advertising and performance analysis, which does not identify individual users

---

### Information Sharing

4.1. We do not sell, trade, or disclose your personal information to third parties, except as necessary for the operation of our services or as required by law.

---

### Information Security

5.1. We take appropriate measures to ensure the security of your personal information. This includes using industry-standard security protocols to prevent unauthorized access, disclosure, alteration, or destruction of your data.

---

### Data Retention

6.1. We retain your personal information for as long as necessary to fulfill the purposes outlined in this Privacy Policy, or as required or permitted by law.

---

### Third-Party Links

7.1. Our website may contain links to third-party websites or services. We are not responsible for the privacy practices of these third parties. We encourage you to review the privacy policies of any third-party websites you visit.

---

### Your Rights and Choices

8.1. You have the right to access, update, or correct inaccuracies in your personal information. You may also request the deletion of your personal information, subject to legal requirements.

8.2. If you have any questions or concerns regarding your personal information or this Privacy Policy, please contact us using the information provided below.

---

### Changes to This Privacy Policy

9.1. We may update this Privacy Policy periodically to reflect changes in our practices or legal obligations. Any significant changes will be communicated by posting a prominent notice on our website or via other communication methods.

---

**Please review this Privacy Policy carefully. By continuing to use our services, you consent to the collection, use, and storage of your personal information as described in this policy.**
`
  },
  aboutUsText: { type: String, required: true, default: 'Your about us text goes here...' },
  aboutUsVisible: { type: Boolean, required: true, default: true },
  displayStats: { type: Boolean, required: true, default: true },
  displayFeatures: { type: Boolean, required: true, default: true },
  displayReviews: { type: Boolean, required: true, default: true },
  displayProductReviews: { type: Boolean, required: true, default: true },
  displayCTABanner: { type: Boolean, required: true, default: true },
  backgroundGradient: { type: Boolean, required: true, default: false },
  logoPath: { type: String, default: '/images/logo.png' },
  websiteFont: { type: String, default: 'Rubik' },
  backgroundImagePath: { type: String, default: '/images/background.jpg' },
  faviconPath: { type: String, default: '/images/favicon.ico' },
  accentColor: { type: String, default: '#5e99ff' },
  discordInviteLink: { type: String, default: 'https://discord.gg/plexdev' },
  siteBannerText: { type: String, default: '' },
  homePageTitle: { type: String, default: 'Welcome to Plex Development' },
  homePageSubtitle: { type: String, default: 'Your destination for high-quality, easy-to-use products. We offer a range of affordable solutions without compromising on excellence.' },
  productsPageTitle: { type: String, default: 'Our Products' },
  productsPageSubtitle: { type: String, default: 'Explore our range of high-quality, easy-to-use digital products, designed to enhance your online presence.' },
  reviewsPageTitle: { type: String, default: 'Customer Reviews' },
  reviewsPageSubtitle: { type: String, default: 'Discover how our products have made a difference for others!' },
  tosPageTitle: { type: String, default: 'Terms of Service' },
  tosPageSubtitle: { type: String, default: 'Please read the terms of service carefully before using our products and services.' },
  privacyPolicyPageTitle: { type: String, default: 'Privacy Policy' },
  privacyPolicyPageSubtitle: { type: String, default: 'Understand how we collect, use, and protect your personal information.' },
  storeName: { type: String, default: 'Plex Development' },
  paymentCurrency: { type: String, default: 'USD' },
  currencySymbol: { type: String, default: '$' },
  customNavTabs: [{ name: { type: String, required: true }, link: { type: String, required: true } }],
  customFooterTabs: [{ name: { type: String, required: true }, link: { type: String, required: true } }],
  footerDescription: { type: String, required: true, default: 'Welcome to Plex Development, your one-stop shop for all your needs. We’re dedicated to providing quality products and a seamless shopping experience. If you have any questions, our team is always ready to assist!' },
  features: [
    { icon: { type: String, required: true, default: 'fas fa-user-friends' }, title: { type: String, required: true, default: 'User-Friendly' }, description: { type: String, required: true, default: 'Easily manage your store with our intuitive interface, no coding required.' }},
    { icon: { type: String, required: true, default: 'fas fa-cogs' }, title: { type: String, required: true, default: 'Highly Customizable' }, description: { type: String, required: true, default: 'Tailor your store to match your brand with extensive customization options.' }},
    { icon: { type: String, required: true, default: 'fas fa-shield-alt' }, title: { type: String, required: true, default: 'Secure' }, description: { type: String, required: true, default: 'Keep your store and customer data safe with our built-in security features.' }}
  ],
  seoTitle: { type: String, default: 'Plex Development - High-Quality Discord Bots, Websites & More' },
  seoDescription: { type: String, default: 'Plex Development provides high-quality Discord bots, custom websites, and other digital products to improve your online presence. Get reliable products and great service tailored to your needs.' },
  seoTags: { type: String, default: 'Plex Development, High Quality Products, Easy to Use, Customer Support, Discord bots, Websites' },
  apiKey: { type: String, default: '' },
  apiEnabled: { type: Boolean, default: false },
  antiPiracyEnabled: { type: Boolean, default: false },
  salesTax: { type: Number, default: 0 },
  discordLoggingChannel: { type: String, default: '' },
  productCategories: [categorySchema],
  // Review settings
  sendReviewsToDiscord: { type: Boolean, default: false },
  discordReviewChannel: { type: String, default: '' },
  minimumReviewLength: { type: Number, default: 30 },
  allowReviewDeletion: { type: Boolean, default: true },
  updatedAt: { type: Date, default: Date.now }
});


settingsSchema.pre('save', function (next) {
  if (!this.features || this.features.length === 0) {
    this.features = [
      {
        icon: 'fas fa-star',
        title: 'High Quality',
        description: 'Our products are crafted with the highest quality standards to ensure reliability and performance.'
      },
      {
        icon: 'fas fa-headset',
        title: 'Customer Support',
        description: 'We offer exceptional customer support to help you get the most out of our products.'
      },
      {
        icon: 'fas fa-bolt',
        title: 'Easy to Use',
        description: 'Designed for ease of use, our products are simple to set up and intuitive to operate.'
      }
    ];
  }

  this.updatedAt = Date.now();
  next();
});
 // %%__NONCE__%%
const Settings = mongoose.model('Settings', settingsSchema);

module.exports = Settings;
