import rateLimit from "express-rate-limit";

export const ratelimit = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: {
    success: false,
    message: "Too many verification requests. Try again later.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});
