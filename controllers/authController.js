const User = require('../models/User');
const Token = require('../models/Token');
const { StatusCodes } = require('http-status-codes');
const CustomError = require('../errors');
const { attachCookiesToResponse, createTokenUser } = require('../utils');
const crypto = require('crypto');
const sendVerificationEmail = require('../utils/sendVerificationEmail');
const sendResetPasswordEmail = require('../utils/sendResetPasswordEmail');
const createHash = require('../utils/createHash');

// 1)
const register = async (req, res) => {
  const { email, name, password } = req.body;

  const emailAlreadyExists = await User.findOne({ email });
  if (emailAlreadyExists) {
    throw new CustomError.BadRequestError('Email already exists');
  }

  // first registered user is an admin
  const isFirstAccount = (await User.countDocuments({})) === 0;
  const role = isFirstAccount ? 'admin' : 'user';

  const verificationToken = crypto.randomBytes(40).toString('hex');

  const user = await User.create({
    name,
    email: email.toLowerCase(),
    password,
    role,
    verificationToken,
  });

  const origin = 'http://localhost:3000';
  const protocol = req.protocol;
  const host = req.get('host');
  const forwardedHost = req.get('x-forwarded-host');
  const forwardedProtocol = req.get('x-forwarded-proto');

  await sendVerificationEmail({
    name: user.name,
    email: user.email,
    verificationToken: user.verificationToken,
    origin,
  });

  res.status(StatusCodes.CREATED).json({
    msg: 'Success, please verify your reg by checking your email..',
    verificationToken: user.verificationToken,
  });
};

// 2)
const verifyEmail = async (req, res) => {
  const { verificationToken, email } = req.body;
  const user = await User.findOne({ email: email.toLowerCase() });

  if (!user) throw new CustomError.UnauthenticatedError('Verification failed');
  if (user.verificationToken !== verificationToken)
    throw new CustomError.UnauthenticatedError('Verification failed');

  user.isVerified = true;
  user.verified = Date.now();
  user.verificationToken = '';

  await user.save();

  res.status(StatusCodes.OK).json({ msg: 'Email verified' });
};

// 3)
const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    throw new CustomError.BadRequestError('Please provide email and password');
  }
  const user = await User.findOne({ email: email.toLowerCase() });

  if (!user) {
    throw new CustomError.UnauthenticatedError('Invalid Credentials');
  }

  const isPasswordCorrect = await user.comparePassword(password);
  if (!isPasswordCorrect) {
    throw new CustomError.UnauthenticatedError('Invalid Credentials');
  }

  if (!user.isVerified) {
    throw new CustomError.UnauthenticatedError(
      'Please check your email for verification'
    );
  }

  const tokenUserPayloadObject = createTokenUser(user);
  // create refresh token
  let refreshToken = '';

  // Check for exixting token
  const existingToken = await Token.findOne({ user: user._id });

  if (existingToken) {
    const { isValid } = existingToken;

    if (!isValid)
      throw new CustomError.UnauthenticatedError('Credentials are invalid');
    refreshToken = existingToken.refreshToken;

    attachCookiesToResponse({
      res,
      user: tokenUserPayloadObject,
      refreshToken,
    });

    res.status(StatusCodes.OK).json({ user: tokenUserPayloadObject });
    return;
  }

  refreshToken = crypto.randomBytes(40).toString('hex');
  const userAgent = req.headers['user-agent'];
  const ip = req.ip;
  const userToken = {
    refreshToken,
    ip,
    userAgent,
    user: user._id,
  };

  await Token.create(userToken);
  attachCookiesToResponse({ res, user: tokenUserPayloadObject, refreshToken });

  res.status(StatusCodes.OK).json({ user: tokenUserPayloadObject });
};

// 4)
const logout = async (req, res) => {
  await Token.findOneAndDelete({ user: req.user.userId });

  res.cookie('accessToken', 'logout', {
    httpOnly: true,
    maxAge: 1,
  });

  res.cookie('refreshToken', 'logout', {
    httpOnly: true,
    maxAge: 1,
  });

  res.status(StatusCodes.OK).json({ msg: 'user logged out!' });
};

// 5)
const forgotPassword = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    throw new CustomError.BadRequestError('Please provide a valid email');
  }

  const user = await User.findOne({ email });

  if (user) {
    passwordToken = crypto.randomBytes(70).toString('hex');
    const origin = 'http://localhost:3000';
    // Send email
    await sendResetPasswordEmail({
      name: user.name,
      email: user.email,
      verificationToken: passwordToken,
      origin,
    });

    const oneMinute = 1000 * 60;
    const passwordTokenExpirationDate = new Date(Date.now() + oneMinute);

    user.passwordToken = createHash(passwordToken);
    user.passwordTokenExpirationDate = passwordTokenExpirationDate;
    await user.save();
  }

  res
    .status(StatusCodes.OK)
    .json({ msg: 'Please check your email for password reset link' });
};

// 6)
const resetPassword = async (req, res) => {
  const { token, email, password } = req.body;

  if (!email || !token || !password) {
    throw new CustomError.BadRequestError('Please provide all values!');
  }

  const user = await User.findOne({ email });

  if (user) {
    const currentDate = new Date();

    if (
      user.passwordToken === createHash(token) &&
      user.passwordTokenExpirationDate > currentDate
    ) {
      user.password = password;
      user.passwordToken = null;
      user.passwordTokenExpirationDate = null;
      await user.save();
    }
  }
  res.send('reset password');
};

module.exports = {
  register,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
};
