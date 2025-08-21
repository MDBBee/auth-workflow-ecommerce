module.exports = {
  host: 'smtp.ethereal.email',
  port: 587,
  secure: false, // true for 465, false for other ports
  auth: {
    user: 'donavon.kling39@ethereal.email',
    pass: 'cZw8sdAwg2y2VxETGh',
  },
  tls: {
    rejectUnauthorized: false, // <--- ADD THIS
  },
};
