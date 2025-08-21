const nodemailer = require('nodemailer');
const nodemailerConfig = require('./nodemailerConfig');

const sendEmail = async ({ to, subject, html }) => {
  // Create a test account or replace with real credentials.
  const transporter = nodemailer.createTransport(nodemailerConfig);

  return transporter.sendMail({
    from: '"Bobby Ugbebor" <bobbyugbebor@gmail.com>',
    to,
    subject,
    html,
  });
};

module.exports = sendEmail;
