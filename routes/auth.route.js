import express from "express";
import {
  register,
  login,
  verifyEmail,
  resendVerification,
  forgotPassword,
  getMe,
  updateProfile,
  deleteAccount,
  logout,
  changePassword,
  resetForgetPassword,
} from "../controllers/auth.controller.js";
import { verifyToken } from "../middlewares/verifyToken.js";
import { ratelimit } from "../middlewares/ratelimit.js";
import { asyncHandler } from "../middlewares/asyncHandler.js";

const router = express.Router();

router.post("/register", asyncHandler(register));
router.post("/login", asyncHandler(login));
router.get("/me", verifyToken, asyncHandler(getMe));
router.patch("/update-me", verifyToken, asyncHandler(updateProfile));
router.delete("/delete-me", verifyToken, asyncHandler(deleteAccount));
router.post("/verify-email", asyncHandler(verifyEmail));
router.post(
  "/resend-verification",
  ratelimit,
  asyncHandler(resendVerification)
);
router.post(
  "/forget-password",
  verifyToken,
  ratelimit,
  asyncHandler(forgotPassword)
);
router.post(
  "/reset-forget-password",
  verifyToken,
  asyncHandler(resetForgetPassword)
);
router.post("/logout", verifyToken, asyncHandler(logout));
router.post("/reset-password", verifyToken, asyncHandler(changePassword));

export default router;
