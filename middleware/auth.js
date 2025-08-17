const jwt = require("jsonwebtoken");
const config = require("config");
const User = require("../models/User");

// Middleware to verify JWT token
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({
        status: "error",
        error: {
          code: "auth/no-token",
          message: "Access token is required",
        },
      });
    }

    // Verify token
    const decoded = jwt.verify(token, config.get("jwt.secret"));

    // Check if user exists and is active
    const user = await User.findById(decoded.userId).select("-password");
    if (!user || !user.isActive) {
      return res.status(401).json({
        status: "error",
        error: {
          code: "auth/user-not-found",
          message: "User not found or inactive",
        },
      });
    }

    // Add user to request object
    req.user = user;
    next();
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({
        status: "error",
        error: {
          code: "auth/invalid-token",
          message: "Invalid token",
        },
      });
    }

    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        status: "error",
        error: {
          code: "auth/token-expired",
          message: "Token expired",
        },
      });
    }

    console.error("Auth middleware error:", error);
    return res.status(500).json({
      status: "error",
      error: {
        code: "auth/verification-failed",
        message: "Token verification failed",
      },
    });
  }
};

// {
//   "equbId": "EQB123456789",  //equb id to payed for
//   "userId": "USR123456789", // paid user id
//   "currentUserId": "", // current user id to check user role
//   "round": 1,   // for which round to pay
//   "amount": 5000,  //amount to pay for round
//   "paymentMethod": "cash",  //methode
//   "notes": "Payment received on time"  //note
// }

// Middleware to check if user has specific role in an equb
const checkEqubRole = (allowedRoles) => {
  return async (req, res, next) => {
    try {
      const { equbId } = req.body;
      const userId = req.user._id;

      // Find the equb and check user's role
      const Equb = require("../models/Equb");
      const equb = await Equb.findOne({ equbId });

      if (!equb) {
        return res.status(404).json({
          status: "error",
          error: {
            code: "equb/not-found",
            message: "Equb not found",
          },
        });
      }

      const member = equb.members.find(
        (m) => m.userId.toString() === userId.toString()
      );
      if (!member) {
        return res.status(403).json({
          status: "error",
          error: {
            code: "equb/not-member",
            message: "You are not a member of this equb",
          },
        });
      }

      if (!allowedRoles.includes(member.role)) {
        return res.status(403).json({
          status: "error",
          error: {
            code: "equb/insufficient-permissions",
            message: "You don't have permission to perform this action",
          },
        });
      }

      req.equb = equb;
      req.member = member;
      next();
    } catch (error) {
      console.error("Role check error:", error);
      return res.status(500).json({
        status: "error",
        error: {
          code: "auth/role-check-failed",
          message: "Role verification failed",
        },
      });
    }
  };
};

// Middleware to check if user is equb admin
const isEqubAdmin = checkEqubRole(["admin", "collector", "judge", "writer"]);

// Middleware factory to check if user has specific role in an equb
const checkPaymentRole = (allowedRoles) => {
  return async (req, res, next) => {
    try {
      // equbId can be in params or body
      const equbId = req.params?.equbId || req.body?.equbId;

      // authenticated user id
      const currentUserId = req.user && req.user._id;
      console.log("Current user ID:", currentUserId);

      if (!equbId) {
        return res.status(400).json({
          status: "error",
          error: {
            code: "validation/missing-field",
            message: "equbId is required",
          },
        });
      }

      // Find the equb and check user's role
      const Equb = require("../models/Equb");
      const equb = await Equb.findOne({ equbId });

      if (!equb) {
        return res.status(404).json({
          status: "error",
          error: { code: "equb/not-found", message: "Equb not found" },
        });
      }

      const member = equb.members.find(
        (m) => m.userId.toString() === currentUserId.toString()
      );

      if (!member) {
        return res.status(403).json({
          status: "error",
          error: {
            code: "equb/not-member",
            message: "You are not a member of this equb",
          },
        });
      }

      // Check role is allowed
      if (!allowedRoles.includes(member.role)) {
        return res.status(403).json({
          status: "error",
          error: {
            code: "equb/insufficient-permissions",
            message: "You don't have permission to perform this action",
          },
        });
      }

      req.equb = equb;
      req.member = member;
      next();
    } catch (error) {
      console.error("Role check error:", error);
      return res.status(500).json({
        status: "error",
        error: {
          code: "auth/role-check-failed",
          message: "Role verification failed",
        },
      });
    }
  };
};

// Shortcut middleware for payment processors (collector, judge, writer)
const isPaymentProcessor = checkPaymentRole(["collector", "judge", "writer"]);

// Middleware to check if a user is a member of an equb (no role restriction)
const isEqubMember = async (req, res, next) => {
  try {
    const equbId = req.params?.equbId || req.body?.equbId;
    const currentUserId = req.user && req.user._id;

    if (!equbId) {
      return res.status(400).json({
        status: "error",
        error: {
          code: "validation/missing-field",
          message: "equbId is required",
        },
      });
    }
    if (!currentUserId) {
      return res.status(401).json({
        status: "error",
        error: { code: "auth/no-token", message: "Authentication required" },
      });
    }

    const Equb = require("../models/Equb");
    const equb = await Equb.findOne({
      equbId,
      "members.userId": currentUserId,
    });
    if (!equb) {
      return res.status(403).json({
        status: "error",
        error: {
          code: "equb/not-member",
          message: "You are not a member of this equb",
        },
      });
    }

    const member = equb.members.find(
      (m) => m.userId.toString() === currentUserId.toString()
    );
    req.equb = equb;
    req.member = member;
    next();
  } catch (error) {
    console.error("isEqubMember error:", error);
    return res.status(500).json({
      status: "error",
      error: {
        code: "auth/role-check-failed",
        message: "Role verification failed",
      },
    });
  }
};

// Shortcut middleware for collector or admin roles
const isCollectorOrAdmin = checkEqubRole(["collector", "admin"]);

// Middleware to require the authenticated user to be the owner of a resource
const isOwner = (req, res, next) => {
  try {
    const currentUserId = req.user && req.user._id;
    const targetUserId = req.params?.userId || req.body?.userId;

    if (!currentUserId) {
      return res.status(401).json({
        status: "error",
        error: { code: "auth/no-token", message: "Authentication required" },
      });
    }

    if (!targetUserId) {
      return res.status(400).json({
        status: "error",
        error: {
          code: "validation/missing-field",
          message: "userId is required",
        },
      });
    }

    if (currentUserId.toString() !== targetUserId.toString()) {
      return res.status(403).json({
        status: "error",
        error: {
          code: "auth/not-owner",
          message: "You don't have permission to perform this action",
        },
      });
    }

    next();
  } catch (error) {
    console.error("isOwner error:", error);
    return res.status(500).json({
      status: "error",
      error: {
        code: "auth/owner-check-failed",
        message: "Owner verification failed",
      },
    });
  }
};

// Middleware to require verified account
const requireVerification = (req, res, next) => {
  try {
    const user = req.user;
    if (!user) {
      return res.status(401).json({
        status: "error",
        error: { code: "auth/no-token", message: "Authentication required" },
      });
    }
    if (!user.isVerified) {
      return res.status(403).json({
        status: "error",
        error: { code: "auth/not-verified", message: "Account not verified" },
      });
    }
    next();
  } catch (error) {
    console.error("requireVerification error:", error);
    return res.status(500).json({
      status: "error",
      error: {
        code: "auth/verification-check-failed",
        message: "Verification check failed",
      },
    });
  }
};

// Rate limiting for authentication endpoints
const authRateLimit = require("express-rate-limit")({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: {
    status: "error",
    error: {
      code: "rate-limit/auth-exceeded",
      message: "Too many authentication attempts, please try again later",
    },
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiting for payment endpoints
const paymentRateLimit = require("express-rate-limit")({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  message: {
    status: "error",
    error: {
      code: "rate-limit/payment-exceeded",
      message: "Too many payment requests, please try again later",
    },
  },
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = {
  authenticateToken,
  checkEqubRole,
  isEqubAdmin,
  isCollectorOrAdmin,
  isEqubMember,
  checkPaymentRole,
  isPaymentProcessor,
  isOwner,
  requireVerification,
  authRateLimit,
  paymentRateLimit,
};
