const express = require("express");
const router = express.Router();
const equbController = require("../controllers/equb.controller");
const {
  authenticateToken,
  isEqubMember,
  isEqubAdmin,
  isPaymentProcessor,
} = require("../middleware/auth");
const {
  validateDiscoverEqubs,
  validateJoinEqub,
  validateGetMyEqubs,
  validateAddMember,
  validateUpdateMemberRole,
} = require("../middleware/validation");

// Apply authentication to all equb routes
router.use(authenticateToken);

// Equb discovery and joining
router.get(
  "/discover-equbs",
  validateDiscoverEqubs,
  equbController.discoverEqubs
);
router.post("/join-equb", validateJoinEqub, equbController.joinEqub);

// User's equbs
router.post("/my-equbs", equbController.getMyEqubs);

// Equb details (requires membership)
router.get("/:equbId", equbController.getEqubDetails);

// Public: list all members (names only)
router.get("/:equbId/members", equbController.getEqubMembers);

// Public: get payment history for a specific member
router.get(
  "/:equbId/members/:userId/payments",
  equbController.getMemberPayments
);

// Equb administration (requires admin role)
router.post(
  "/:equbId/addMember",
  isEqubAdmin,
  validateAddMember,
  equbController.addMember
);
router.delete(
  "/:equbId/members/:userId",
  isEqubAdmin,
  equbController.removeMember
);
router.put(
  "/:equbId/members/:userId/role",
  isEqubAdmin,
  validateUpdateMemberRole,
  equbController.updateMemberRole
);

router.post(
  "/:equbId/announce-winner",
  isPaymentProcessor,
  equbController.announceWinner
);

module.exports = router;
