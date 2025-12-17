const fs = require('fs');
const yaml = require("js-yaml")
const config = yaml.load(fs.readFileSync('./config.yml', 'utf8'));
const axios = require('axios');
const color = require('ansi-colors');
const settingsModel = require('./models/settingsModel')
const { client } = require("./index.js")
const Discord = require('discord.js');
const path = require('path');
const crypto = require('crypto');
const unzipper = require('unzipper');
const archiver = require('archiver');
const { PassThrough } = require('stream');

const sgMail = require('@sendgrid/mail');
const nodemailer = require('nodemailer');



if (config.EmailSettings.Enabled && config.EmailSettings.provider === "sendgrid") {
  sgMail.setApiKey(config.EmailSettings.sendGrid.token);
}

// Function to send email using SendGrid
async function sendWithSendGrid(email, subject, htmlContent) {
  const msg = {
    to: email,
    from: config.EmailSettings.fromEmail,
    subject: subject,
    html: htmlContent,
  };

  try {
    await sgMail.send(msg);
  } catch (error) {
    console.error('Error sending email with SendGrid:', error);
    throw error;
  }
}

// Function to send email using SMTP
async function sendWithSMTP(email, subject, htmlContent) {
  const transporter = nodemailer.createTransport({
    host: config.EmailSettings.smtp.host,
    port: config.EmailSettings.smtp.port,
    secure: config.EmailSettings.smtp.secure,
    auth: {
      user: config.EmailSettings.smtp.user,
      pass: config.EmailSettings.smtp.password,
    },
  });

  transporter.verify((error, success) => {
    if (error) {
      console.error('SMTP Configuration Error:', error);
    } else {
      console.log('SMTP Server is ready to send emails');
    }
  });

  const mailOptions = {
    from: config.EmailSettings.fromEmail,
    to: email,
    subject: subject,
    html: htmlContent,
  };

  try {
    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error('Error sending email with SMTP:', error);
    throw error;
  }
}

// Unified function to send email
exports.sendEmail = async function (email, subject, htmlContent) {
  try {
    if (config.EmailSettings.provider === "sendgrid") {
      await sendWithSendGrid(email, subject, htmlContent);
    } else if (config.EmailSettings.provider === "smtp") {
      await sendWithSMTP(email, subject, htmlContent);
    } else {
      throw new Error('Invalid email provider specified in the configuration.');
    }
  } catch (error) {
    console.error('Failed to send email:', error);
    throw error;
  }
}
  
  // Function to generate email content
  exports.generateEmailContent = async function ({
    paymentMethod,
    transactionId,
    userId,
    username,
    userEmail,
    discordId = null,
    products,
    totalPaid,
    discountCode = null,
    discountPercentage = null,
    salesTax = null,
    salesTaxAmount = null,
    nextPaymentId,
    globalSettings,
    config,
  }) {
    return `
    <div style="font-family: 'Arial', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #161b22; border-radius: 12px; border: 2px solid ${globalSettings.accentColor};">
      <h1 style="color: #ffffff; border-bottom: 2px solid ${globalSettings.accentColor}; padding-bottom: 10px;">Payment Invoice (#${nextPaymentId})</h1>
      <p style="font-size: 16px; color: #c9d1d9;">Thank you for your purchase!</p>
  
      <div style="background-color: #21262d; padding: 20px; border-radius: 10px; border: 1px solid ${globalSettings.accentColor}; margin-bottom: 20px;">
        <p style="color: #8b949e;"><strong>Payment To:</strong></p>
        <p style="margin: 5px 0; font-size: 14px; color: #ffffff;"><strong>${globalSettings.storeName}</strong></p>
        <p style="margin: 5px 0; font-size: 14px; color: #c9d1d9;"><strong>${config.baseURL}</strong></p>
      </div>
  
      <div style="background-color: #21262d; padding: 20px; border-radius: 10px; border: 1px solid ${globalSettings.accentColor}; margin-bottom: 20px;">
        <p style="color: #8b949e;"><strong>Payment Details:</strong></p>
        <p style="margin: 5px 0; font-size: 14px; color: #c9d1d9;"><strong>Transaction ID:</strong> ${transactionId} (${paymentMethod})</p>
        <p style="margin: 5px 0; font-size: 14px; color: #c9d1d9;"><strong>User ID:</strong> ${userId}</p>
        <p style="margin: 5px 0; font-size: 14px; color: #c9d1d9;"><strong>Username:</strong> ${username}</p>
        <p style="margin: 5px 0; font-size: 14px; color: #c9d1d9;"><strong>Email:</strong> ${userEmail}</p>
        ${discordId ? `<p style="margin: 5px 0; font-size: 14px; color: #c9d1d9;"><strong>Discord ID:</strong> ${discordId}</p>` : ''}
      </div>
  
      <h2 style="color: #ffffff; border-bottom: 2px solid ${globalSettings.accentColor}; padding-bottom: 10px; margin-bottom: 20px;">Order Details</h2>
      <ul style="list-style-type: none; padding: 0;">
        ${products.map(product => `
          <li style="background-color: #21262d; padding: 15px; margin-bottom: 15px; border-radius: 10px; border: 1px solid ${globalSettings.accentColor};">
            <strong style="color: #ffffff;">${product.name}</strong>
            <span style="float: right; color: ${globalSettings.accentColor};">$${product.price.toFixed(2)}</span>
          </li>`).join('')}
      </ul>
  
      <div style="background-color: #21262d; padding: 20px; border-radius: 10px; border: 1px solid ${globalSettings.accentColor};">
        <p style="margin: 5px 0; font-size: 16px; color: #ffffff;"><strong>Total Paid:</strong>
          <span style="color: ${globalSettings.accentColor};">$${totalPaid.toFixed(2)}</span>
        </p>
        ${discountCode ? `<p style="margin: 5px 0; font-size: 14px; color: #28a745;"><strong>Discount Applied:</strong> ${discountCode} (${discountPercentage}% off)</p>` : ''}
        ${salesTax ? `<p style="margin: 5px 0; font-size: 14px; color: #28a745;"><strong>Sales Tax Applied:</strong> ${salesTax}% ($${salesTaxAmount.toFixed(2)})</p>` : ''}
      </div>
    </div>
    `;
  }

  exports.sendDiscordLog = async function (title, description) {
    try {
      const settings = await settingsModel.findOne();
      const channelId = settings.discordLoggingChannel;
  
      if(!channelId) return console.error('No Discord logging channel ID is set in the settings.');
  
      const channel = await client.channels.fetch(channelId);
      if (!channel || !channel.isTextBased()) return console.error('Unable to find the specified Discord channel or the channel is not a text channel.');
  
      const embed = new Discord.EmbedBuilder()
      .setTitle(title || 'Log')
      .setDescription(description || 'Unknown')
      .setTimestamp()
      .setColor(settings.accentColor);

      await channel.send({ embeds: [embed] });
    } catch (error) {
      console.error('Error sending Discord log:', error);
    }
  };
  
  exports.processFileWithPlaceholders = async function (filePath, replacements) {
    try {
        let placeholderFound = false;
        const tempFiles = []; // Array to keep track of all temporary files

        // Function to generate a unique filename
        function generateUniqueFilename(baseName) {
            const randomBytes = crypto.randomBytes(16).toString('hex');
            return `temp-${Date.now()}-${randomBytes}-${baseName}`;
        }

        // Replace placeholders in text content
        function replacePlaceholders(content, replacements) {
            return content.replace(/%%__(\w+)__%%/g, (match, placeholder) => {
                if (replacements[placeholder]) {
                    placeholderFound = true;
                    return replacements[placeholder];
                }
                return match;
            });
        }

        // Replace placeholders in binary files like .class
        function replacePlaceholdersInBinary(buffer, replacements) {
            const content = buffer.toString('utf-8'); // Convert binary to string
            const replacedContent = replacePlaceholders(content, replacements);
            if (replacedContent !== content) {
                placeholderFound = true;
                return Buffer.from(replacedContent, 'utf-8');
            }
            return buffer; // Return original buffer if no replacement is done
        }

        async function processZipOrJarFile(zipFilePath, replacements) {
            const tempZipPath = path.join(path.dirname(zipFilePath), generateUniqueFilename(path.basename(zipFilePath)));
            tempFiles.push(tempZipPath); // Track the temporary file
        
            const output = fs.createWriteStream(tempZipPath);
            const archive = archiver('zip');
        
            return new Promise((resolve, reject) => {
                archive.on('error', (err) => {
                    // Silently ignore the archive errors
                    if(config.DebugMode) console.error(`Archive error: ${err}`);
                    resolve(zipFilePath); // Continue without failing the entire process
                });
        
                output.on('close', () => {
                    if (placeholderFound) {
                        resolve(tempZipPath);
                    } else {
                        resolve(zipFilePath);
                    }
                });
        
                archive.pipe(output);
        
                // Collect promises for all entries
                const entryPromises = [];
        
                const processEntry = async (entry) => {
                    try {
                        let content = await entry.buffer();
        
                        if (entry.path.match(/\.(zip|jar|war)$/i)) {
                            const nestedFilePath = path.join(path.dirname(tempZipPath), generateUniqueFilename(path.basename(entry.path)));
                            fs.writeFileSync(nestedFilePath, content);
                            tempFiles.push(nestedFilePath); // Track the temporary file
        
                            const nestedProcessedPath = await processZipOrJarFile(nestedFilePath, replacements);
        
                            if (fs.existsSync(nestedProcessedPath)) {
                                archive.append(fs.createReadStream(nestedProcessedPath), { name: entry.path });
                            }
                        } else if (entry.path.match(/\.(class)$/i)) {
                            const replacedContent = replacePlaceholdersInBinary(content, replacements);
                            archive.append(replacedContent, { name: entry.path });
                        } else if (entry.path.match(/\.(txt|js|md|json|etc)$/i)) {
                            const replacedContent = replacePlaceholders(content.toString(), replacements);
                            archive.append(replacedContent, { name: entry.path });
                        } else {
                            archive.append(content, { name: entry.path });
                        }
                    } catch (err) {
                        // Silently log the error and continue with the next file
                        if(config.DebugMode) console.error(`Error processing entry ${entry.path}:`, err);
                        entry.autodrain(); // Ignore the error and skip this entry
                    }
                };
        
                fs.createReadStream(zipFilePath)
                    .pipe(unzipper.Parse())
                    .on('entry', (entry) => {
                        entryPromises.push(processEntry(entry));
                    })
                    .on('finish', async () => {
                        // Wait for all entries to finish processing
                        await Promise.all(entryPromises);
                        // Finalize the archive after all entries are processed
                        archive.finalize();
                    })
                    .on('error', (err) => {
                        if(config.DebugMode) console.error(`Unzip operation error: ${err}`);
                        resolve(zipFilePath); // Ignore the error and continue
                    });
            });
        }

        // Check if the file is a zip, jar, or war file
        if (filePath.endsWith('.zip') || filePath.endsWith('.jar') || filePath.endsWith('.war')) {
            const resultPath = await processZipOrJarFile(filePath, replacements);

            // Return the path to the final archive file, leaving temporary files in place for now
            return resultPath;
        } else {
            const content = fs.readFileSync(filePath);
            let processedContent;

            if (filePath.endsWith('.class')) {
                // Process .class files as binary
                processedContent = replacePlaceholdersInBinary(content, replacements);
            } else {
                // Process text files
                processedContent = replacePlaceholders(content.toString(), replacements);
            }

            if (!placeholderFound) {
                return filePath;
            }

            const tempFilePath = path.join(path.dirname(filePath), generateUniqueFilename(path.basename(filePath)));
            tempFiles.push(tempFilePath); // Track the temporary file

            // Ensure the directory exists
            fs.mkdirSync(path.dirname(tempFilePath), { recursive: true });

            fs.writeFileSync(tempFilePath, processedContent);
            return tempFilePath;
        }
    } catch (error) {
        if(config.DebugMode) console.error('Error processing file with placeholders:', error);
        throw error;
    }
};

exports.generateNonce = async function () {
    const randomPart = crypto.randomBytes(6).toString('base64url');
    const timestampPart = Date.now().toString(36).slice(-3);
    const nonce = (randomPart + timestampPart).slice(0, 13);
    return nonce;
}