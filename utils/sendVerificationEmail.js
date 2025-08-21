const sendEmail = require('./sendEmail');

const sendVerificationEmail = async ({
  name,
  email,
  verificationToken,
  origin,
}) => {
  const message =
    '<h1>Welcome to B-store</h1><p>Please confirm your email by clicking on the following link: </p>';

  return sendEmail({
    to: email,
    subject: 'Email confirmation',
    html: `<h4>Hello, ${name}</h4> ${message}`,
  });
};

module.exports = sendVerificationEmail;
