import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import { generateTokenAndSetCookie } from "../lib/generateTokenAndSetCookie.js";
import nodemailer from "nodemailer";
import jwt from "jsonwebtoken";
import { v2 as cloudinary } from "cloudinary";
import { asyncHandler } from "../middlewares/asyncHandler.js";
import { AppError } from "../utils/AppError.js";

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: "ahmdblack.0@gmail.com",
    pass: "qpitagpmolqshrvu",
  },
  tls: {
    rejectUnauthorized: false,
  },
});

const generateVerificationCode = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

export const register = asyncHandler(async (req, res, next) => {
  let { fullName, email, password, username, profileImg } = req.body;

  const existingUser = await User.findOne({ email });
  if (existingUser) throw new AppError("User already exists", 400);

  if (profileImg) {
    const uploaded = await cloudinary.uploader.upload(profileImg, {
      folder: "users/profile_images",
    });
    profileImg = uploaded.secure_url;
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const verificationCode = generateVerificationCode();
  const verificationCodeExpires = Date.now() + 10 * 60 * 1000; // 10 minutes

  const user = await User.create({
    fullName,
    email,
    username,
    password: hashedPassword,
    verificationCode,
    verificationCodeExpires,
    isVerified: false,
    profileImg,
  });

  await transporter.sendMail({
    from: `"My App" <${process.env.EMAIL_USER}>`,
    to: user.email,
    subject: "Verify your email",
    html: `
      <h2>Hello ${user.fullName},</h2>
      <p>Your verification code is:</p>
      <h1>${verificationCode}</h1>
      <p>This code expires in 10 minutes.</p>
    `,
  });

  res.status(201).json({
    success: true,
    message: "Verification code sent to your email.",
    email: user.email,
  });
});

export const verifyEmail = asyncHandler(async (req, res) => {
  const { email, code } = req.body;

  const user = await User.findOne({
    email,
    verificationCode: code,
    verificationCodeExpires: { $gt: Date.now() },
  });

  if (!user) throw new AppError("Invalid or expired verification code", 400);

  user.isVerified = true;
  user.verificationCode = undefined;
  user.verificationCodeExpires = undefined;
  await user.save();

  const tokenPayload = {
    userId: user._id,
    role: user.role,
    isVerified: true,
  };

  const jwtToken = jwt.sign(tokenPayload, process.env.JWT_SECRET_KEY, {
    expiresIn: "7d",
  });

  res.cookie("jwt", jwtToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  res.status(200).json({
    success: true,
    message: "Email verified successfully!",
  });
});

export const resendVerification = asyncHandler(async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) throw new AppError("User not found", 404);
  if (user.isVerified) throw new AppError("Email already verified", 400);

  const verificationCode = generateVerificationCode();
  user.verificationCode = verificationCode;
  user.verificationCodeExpires = Date.now() + 10 * 60 * 1000;
  await user.save();

  await transporter.sendMail({
    from: `"My App" <${process.env.EMAIL_USER}>`,
    to: user.email,
    subject: "Resend Verification Code",
    html: `
      <h2>Hello ${user.fullName},</h2>
      <p>Your new verification code is:</p>
      <h1>${verificationCode}</h1>
    `,
  });

  res.json({ success: true, message: "Verification code resent." });
});

export const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email }).select("+password +isVerified");
  if (!user) throw new AppError("Invalid credentials", 400);

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) throw new AppError("Invalid credentials", 400);

  if (!user.isVerified)
    throw new AppError("Please verify your email to login", 401);

  generateTokenAndSetCookie(user, res);
  res.status(200).json({ success: true, message: "Logged in successfully" });
});

export const getMe = asyncHandler(async (req, res) => {
  const user = await User.findById(req.userId).select(
    "-password -__v -verificationCode -verificationCodeExpires -resetPasswordToken -resetPasswordExpires"
  );
  if (!user) throw new AppError("User not found", 404);

  res.status(200).json({ success: true, user });
});

export const updateProfile = asyncHandler(async (req, res) => {
  const { fullName, email, username, profileImg } = req.body;

  const updates = {};
  if (fullName) updates.fullName = fullName;
  if (email) updates.email = email;
  if (username) updates.username = username;

  if (profileImg) {
    const uploadedProfile = await cloudinary.uploader.upload(profileImg, {
      folder: "users/profile_images",
    });
    updates.profileImg = uploadedProfile.secure_url;
  }

  const user = await User.findByIdAndUpdate(req.userId, updates, {
    new: true,
    runValidators: true,
  }).select(
    "-password -__v -verificationCode -verificationCodeExpires -resetPasswordToken -resetPasswordExpires"
  );

  if (!user) throw new AppError("User not found", 404);

  res.status(200).json({
    success: true,
    message: "Profile updated successfully",
    user,
  });
});

export const changePassword = asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = await User.findById(req.userId);
  if (!user) throw new AppError("User not found", 404);

  const isMatch = await bcrypt.compare(currentPassword, user.password);
  if (!isMatch) throw new AppError("Current password is incorrect", 400);

  user.password = await bcrypt.hash(newPassword, 10);
  await user.save();

  res
    .status(200)
    .json({ success: true, message: "Password changed successfully" });
});

export const deleteAccount = asyncHandler(async (req, res) => {
  const { password } = req.body;
  const user = await User.findById(req.userId).select("+password");
  if (!user) throw new AppError("User not found", 404);

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) throw new AppError("Password is incorrect", 400);

  await user.deleteOne();
  res.clearCookie("jwt", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Lax",
  });

  res.status(200).json({ success: true, message: "Account deleted" });
});

export const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) throw new AppError("User not found", 404);

  const resetCode = generateVerificationCode();
  user.resetPasswordCode = resetCode;
  user.resetPasswordExpires = Date.now() + 10 * 60 * 1000;
  await user.save();

  await transporter.sendMail({
    from: `"My App" <${process.env.EMAIL_USER}>`,
    to: user.email,
    subject: "Reset your password",
    html: `
      <h2>Password Reset Code</h2>
      <p>Use this code to reset your password:</p>
      <h1>${resetCode}</h1>
    `,
  });

  res.json({ success: true, message: "Reset code sent to your email" });
});

export const resetForgetPassword = asyncHandler(async (req, res) => {
  const { email, code, newPassword } = req.body;
  const user = await User.findOne({
    email,
    resetPasswordCode: code,
    resetPasswordExpires: { $gt: Date.now() },
  });
  if (!user) throw new AppError("Invalid or expired reset code", 400);

  user.password = await bcrypt.hash(newPassword, 10);
  user.resetPasswordCode = undefined;
  user.resetPasswordExpires = undefined;
  await user.save();

  res.status(200).json({
    success: true,
    message: "Password reset successfully. You can now log in.",
  });
});

export const logout = asyncHandler(async (req, res) => {
  res.cookie("jwt", "", {
    httpOnly: true,
    expires: new Date(0),
    sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
    secure: process.env.NODE_ENV === "production",
  });
  res.status(200).json({ success: true, message: "Logged out successfully" });
});
