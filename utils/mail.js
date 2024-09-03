const nodemailer = require('nodemailer');

const sendMail = async (mailOptions) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    logger: true,
    auth: {
      user: process.env.GMAIL_USERNAME,
      pass: process.env.GOOGLE_APP_PASSWORD
    }
  });

  const options = {
    to: mailOptions.to,
    from: {
      name: 'Sumit Prasad from Govt Job ☯️',
      address: 'sumitprasad303@gmail.com'
    },
    subject: mailOptions.subject,
    text: mailOptions.text
  };

  await transporter.sendMail(options);
};

module.exports = sendMail;
