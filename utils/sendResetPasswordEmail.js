const sendEmail = require('./sendEmail');

const sendResetPasswordEmail = async ({
  name,
  email,
  verificationToken,
  origin,
}) => {
  const resetPasswordUrl = `${origin}/user/verify-email?token=${verificationToken}&email=${email}`;

  const message = `<h1>Welcome to B-store</h1><p>Please reset your password by following the link: <a href="${resetPasswordUrl}" target="_blank">Reset Password</a> </p>`;

  return sendEmail({
    to: email,
    subject: 'Email confirmation',
    html: `<h4>Hello, ${name}</h4> ${message}`,
  });
};

module.exports = sendResetPasswordEmail;
