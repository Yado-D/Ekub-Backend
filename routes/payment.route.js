const express = require("express");
const router = express.Router();
const paymentController = require("../controllers/payment.controller");
const {
  authenticateToken,
  isEqubMember,
  isCollectorOrAdmin,
  isPaymentProcessor,
  paymentRateLimit,
} = require("../middleware/auth");
const {
  validatePaymentHistory,
  validateProcessPayment,
  validateUnpaidMembers,
} = require("../middleware/validation");

// Note: do not apply authentication globally so some endpoints can be public.
// Apply rate limiting to payment processing route specifically.

// Payment history and summary (requires equb membership)
router.get(
  "/:equbId/payment-history",
  // public endpoint: optional userId query to filter by member
  validatePaymentHistory,
  paymentController.getPaymentHistory
);
router.get(
  "/:equbId/unpaid-members",
  validateUnpaidMembers,
  paymentController.getUnpaidMembers
);
router.get(
  "/:equbId/payment-summary",
  isEqubMember,
  paymentController.getPaymentSummary
);

// Payment processing (requires collector or admin role)
router.post(
  "/process-payment",
  authenticateToken,
  isPaymentProcessor,
  paymentRateLimit,
  validateProcessPayment,
  paymentController.processPayment
);

// Payment management (requires collector or admin role)
router.put(
  "/:paymentId/mark-unpaid",
  authenticateToken,
  isCollectorOrAdmin,
  paymentController.markPaymentAsUnpaid
);
router.put(
  "/:paymentId/cancel",
  authenticateToken,
  isCollectorOrAdmin,
  paymentController.cancelPayment
);

module.exports = router;
