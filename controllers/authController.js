const User = require('../models/User');
const Token = require('../models/Token');
const { StatusCodes } = require('http-status-codes');
const CustomError = require('../errors');
const { attachCookiesToResponse, createTokenUser } = require('../utils');
const crypto = require('crypto');
const sendVerificationEmail = require('../utils/sendVerificationEmail');

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

  res.status(StatusCodes.OK).json({ user: tokenUser });
};

const logout = async (req, res) => {
  await Token.findOneAndDelete({ user: req.user.userId });

  res.cookie('accessToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  });

  res.cookie('refreshToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  });

  res.status(StatusCodes.OK).json({ msg: 'user logged out!' });
};

module.exports = {
  register,
  login,
  logout,
  verifyEmail,
};
