const Equb = require("../models/Equb");
const User = require("../models/User");
const Payment = require("../models/Payment");
const Notification = require("../models/Notification");

// Discover/Filter Available Equbs
const discoverEqubs = async (req, res) => {
  try {
    const {
      type,
      roundDuration,
      savingAmount,
      page = 1,
      limit = 10,
    } = req.query;
    const userId = req.user._id;

    // Build query
    const query = { isActive: true };

    if (type && type !== "all") {
      query.type = type;
    }

    if (roundDuration && roundDuration !== "all") {
      query.roundDuration = roundDuration;
    }

    if (savingAmount) {
      query.saving = { $lte: parseInt(savingAmount) };
    }

    // Get total count
    const total = await Equb.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

    // Get equbs with pagination
    const equbs = await Equb.find(query)
      .populate("createdBy", "fullName")
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    // Check if user is already a member of each equb
    const equbsWithMembership = equbs.map((equb) => {
      const member = equb.members.find(
        (m) => m.userId.toString() === userId.toString()
      );
      return {
        equbId: equb.equbId,
        name: equb.name,
        description: equb.description,
        type: equb.type,
        roundDuration: equb.roundDuration,
        saving: equb.saving,
        membersNum: equb.membersNum,
        maxMembers: equb.maxMembers,
        startDate: equb.startDate,
        location: equb.location,
        createdBy: equb.createdBy.fullName,
        isJoined: !!member,
      };
    });

    res.status(200).json({
      status: "success",
      data: {
        equbs: equbsWithMembership,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1,
        },
      },
    });
  } catch (error) {
    console.error("Discover equbs error:", error);
    res.status(500).json({
      status: "error",
      error: {
        code: "equb/discovery-failed",
        message: "Failed to discover equbs",
      },
    });
  }
};

// Join Equb
const joinEqub = async (req, res) => {
  try {
    const { equbId, participationType, formNumber, secretNumber } = req.body;
    const userId = req.user._id;

    // Find the equb
    const equb = await Equb.findOne({ equbId, isActive: true });
    if (!equb) {
      return res.status(404).json({
        status: "error",
        error: {
          code: "equb/not-found",
          message: "Equb not found",
        },
      });
    }

    // Check if equb is private and secret number is required
    if (equb.type === "private" && !secretNumber) {
      return res.status(400).json({
        status: "error",
        error: {
          code: "equb/secret-required",
          message: "Secret number is required for private equbs",
        },
      });
    }

    // Check if secret number is correct for private equbs
    if (equb.type === "private" && equb.secretNumber !== secretNumber) {
      return res.status(400).json({
        status: "error",
        error: {
          code: "equb/invalid-secret",
          message: "Invalid secret number",
        },
      });
    }

    // Check if user is already a member
    const existingMember = equb.members.find(
      (m) => m.userId.toString() === userId.toString()
    );
    if (existingMember) {
      return res.status(400).json({
        status: "error",
        error: {
          code: "equb/already-member",
          message: "You are already a member of this equb",
        },
      });
    }

    // Check if equb is full
    if (equb.membersNum >= equb.maxMembers) {
      return res.status(400).json({
        status: "error",
        error: {
          code: "equb/full",
          message: "Equb is full",
        },
      });
    }

    // Check if form number is available
    const formNumberTaken = equb.members.some(
      (m) => m.formNumber === formNumber
    );
    if (formNumberTaken) {
      return res.status(400).json({
        status: "error",
        error: {
          code: "equb/form-number-taken",
          message: "Form number is already taken",
        },
      });
    }

    // Get user details
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        status: "error",
        error: {
          code: "user/not-found",
          message: "User not found",
        },
      });
    }

    // Add user to equb
    await equb.addMember(userId, {
      name: user.fullName,
      participationType,
      formNumber,
      role: "member",
    });

    // Create notification for equb admin
    const adminMember = equb.members.find((m) => m.role === "admin");
    if (adminMember) {
      await Notification.createEqubNotification(adminMember.userId, equb._id, {
        title: "New Member Joined",
        message: `${user.fullName} has joined your equb ${equb.name}`,
        priority: "medium",
        actionUrl: `/equb/${equb.equbId}/members`,
      });
    }

    res.status(200).json({
      status: "success",
      message: "Successfully joined the equb",
      data: {
        equbId: equb.equbId,
        participationType,
        formNumber,
      },
    });
  } catch (error) {
    console.error("Join equb error:", error);
    res.status(500).json({
      status: "error",
      error: {
        code: "equb/join-failed",
        message: "Failed to join equb",
      },
    });
  }
};

// Get My Equbs
const getMyEqubs = async (req, res) => {
  try {
    const userId = req.user._id; // Auth middleware should already set req.user

    // Check if the user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        status: "error",
        error: {
          code: "user/not-found",
          message: "User not found",
        },
      });
    }

    const Equb = require("../models/Equb");

    // Find all equbs where the user is an active member
    const equbs = await Equb.find({
      "members.userId": userId,
      "members.isActive": true,
    })
      .populate("members.userId", "fullName")
      .sort({ "members.joinedDate": -1 });

    // Map response
    const myEqubs = equbs.map((equb) => {
      const member = equb.members.find(
        (m) => m.userId._id.toString() === userId.toString()
      );

      // Calculate next payment date
      let nextPaymentDate = new Date(equb.startDate);
      if (equb.roundDuration === "weekly") {
        nextPaymentDate.setDate(
          nextPaymentDate.getDate() + equb.currentRound * 7
        );
      } else if (equb.roundDuration === "monthly") {
        nextPaymentDate.setMonth(
          nextPaymentDate.getMonth() + equb.currentRound
        );
      } else if (equb.roundDuration === "daily") {
        nextPaymentDate.setDate(nextPaymentDate.getDate() + equb.currentRound);
      }

      // Payment status for current round
      const currentRoundPayment = member.paymentHistory.find(
        (p) => p.roundNumber === equb.currentRound
      );
      const paymentStatus = currentRoundPayment
        ? currentRoundPayment.status
        : "pending";

      return {
        equbId: equb.equbId,
        name: equb.name,
        participationType: member.participationType,
        formNumber: member.formNumber,
        role: member.role,
        saving: equb.saving,
        roundDuration: equb.roundDuration,
        nextPaymentDate,
        paymentStatus,
        totalMembers: equb.membersNum,
        activeMembers: equb.members.filter((m) => m.isActive).length,
      };
    });

    res.status(200).json({
      status: "success",
      data: myEqubs,
    });
  } catch (error) {
    console.error("Get my equbs error:", error);
    res.status(500).json({
      status: "error",
      error: {
        code: "equb/get-my-equbs-failed",
        message: "Failed to get my equbs",
      },
    });
  }
};

// Get Equb Details
const getEqubDetails = async (req, res) => {
  try {
    const { equbId } = req.params;
    const userId = req.user._id;

    const equb = await Equb.findOne({ equbId, isActive: true })
      .populate("createdBy", "fullName phoneNumber")
      .populate("members.userId", "fullName phoneNumber")
      .populate("collectorsInfo.userId", "fullName phoneNumber")
      .populate("judgInfo.userId", "fullName phoneNumber")
      .populate("writersInfo.userId", "fullName phoneNumber");

    if (!equb) {
      return res.status(404).json({
        status: "error",
        error: {
          code: "equb/not-found",
          message: "Equb not found",
        },
      });
    }

    // Check if user is a member
    const member = equb.members.find(
      (m) => m.userId._id.toString() === userId.toString()
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

    // Calculate next round date
    let nextRoundDate = new Date(equb.startDate);
    if (equb.roundDuration === "weekly") {
      nextRoundDate.setDate(nextRoundDate.getDate() + equb.currentRound * 7);
    } else if (equb.roundDuration === "monthly") {
      nextRoundDate.setMonth(nextRoundDate.getMonth() + equb.currentRound);
    } else if (equb.roundDuration === "daily") {
      nextRoundDate.setDate(nextRoundDate.getDate() + equb.currentRound);
    }

    // Determine equb level
    const level = equb.currentRound > 12 ? "old" : "new";

    const equbDetails = {
      equbId: equb.equbId,
      name: equb.name,
      description: equb.description,
      membersNum: equb.membersNum,
      maxMembers: equb.maxMembers,
      saving: equb.saving,
      level,
      type: equb.type,
      roundDuration: equb.roundDuration,
      startDate: equb.startDate,
      nextRoundDate,
      currentRound: equb.currentRound,
      totalRounds: equb.totalRounds,
      bankAccountDetail: equb.bankAccountDetail,
      collectorsInfo: equb.collectorsInfo.map((collector) => ({
        userId: collector.userId._id,
        name: collector.userId.fullName,
        phone: collector.userId.phoneNumber,
      })),
      judgInfo: equb.judgInfo.map((judge) => ({
        userId: judge.userId._id,
        name: judge.userId.fullName,
        phone: judge.userId.phoneNumber,
      })),
      writersInfo: equb.writersInfo.map((writer) => ({
        userId: writer.userId._id,
        name: writer.userId.fullName,
        phone: writer.userId.phoneNumber,
      })),
      members: equb.members.map((member) => ({
        userId: member.userId._id,
        name: member.userId.fullName,
        participationType: member.participationType,
        formNumber: member.formNumber,
        role: member.role,
        paymentHistory: member.paymentHistory,
      })),
    };

    res.status(200).json({
      status: "success",
      data: equbDetails,
    });
  } catch (error) {
    console.error("Get equb details error:", error);
    res.status(500).json({
      status: "error",
      error: {
        code: "equb/get-details-failed",
        message: "Failed to get equb details",
      },
    });
  }
};

// Get all members names for an equb (public)
const getEqubMembers = async (req, res) => {
  try {
    const { equbId } = req.params;
    const equb = await Equb.findOne({ equbId }).populate('members.userId', 'fullName');
    if (!equb) return res.status(404).json({ status: 'error', error: { code: 'equb/not-found', message: 'Equb not found' } });

    const members = equb.members.map(m => ({ name: m.name || (m.userId && m.userId.fullName) || null }));
    res.status(200).json({ status: 'success', data: members });
  } catch (err) {
    console.error('Get equb members error:', err);
    res.status(500).json({ status: 'error', error: { code: 'equb/get-members-failed', message: 'Failed to get members' } });
  }
};

// Get payment history for a specific member (public)
const getMemberPayments = async (req, res) => {
  try {
    const { equbId, userId } = req.params;
    // resolve userId if it's app id
    let targetUser = null;
    if (/^U[A-Z0-9]{9}$/.test(userId)) targetUser = await User.findOne({ userId: userId });
    else targetUser = await User.findById(userId);
    if (!targetUser) return res.status(404).json({ status: 'error', error: { code: 'user/not-found', message: 'User not found' } });

    const equb = await Equb.findOne({ equbId });
    if (!equb) return res.status(404).json({ status: 'error', error: { code: 'equb/not-found', message: 'Equb not found' } });

    // Fetch payments
    const payments = await Payment.find({ equbId: equb._id, userId: targetUser._id }).populate('processedBy', 'userId fullName');

    const history = payments.map(p => {
      // determine processor id (handle populated doc or plain ObjectId)
      let processorId = null;
      if (p.processedBy) {
        processorId = p.processedBy._id ? p.processedBy._id.toString() : p.processedBy.toString();
      }

      // find the processor's role within this equb
      let paidByRole = null;
      if (processorId) {
        const processorMember = equb.members.find(m => m.userId.toString() === processorId);
        paidByRole = processorMember ? processorMember.role : null;
      }

      return {
        paymentMethod: p.paymentMethod,
        amount: p.amountPaid || p.amount,
        date: p.paidDate,
        paidBy: paidByRole
      };
    });
    res.status(200).json({ status: 'success', data: history });
  } catch (err) {
    console.error('Get member payments error:', err);
    res.status(500).json({ status: 'error', error: { code: 'payment/get-member-failed', message: 'Failed to get payments' } });
  }
};

// Announce winner for current round (collectors/judges/writers only)
const announceWinner = async (req, res) => {
  try {
    const { equbId } = req.params;
    const { formNumber } = req.body;
    // req.member is set by middleware which ensures role
    if (!formNumber) return res.status(400).json({ status: 'error', error: { code: 'validation/missing-field', message: 'formNumber is required' } });

    const equb = await Equb.findOne({ equbId });
    if (!equb) return res.status(404).json({ status: 'error', error: { code: 'equb/not-found', message: 'Equb not found' } });

    // find member by formNumber
    const member = equb.members.find(m => m.formNumber === formNumber);
    if (!member) return res.status(404).json({ status: 'error', error: { code: 'equb/member-not-found', message: 'Member not found' } });

    // mark winner in equb (simple field)
    equb.winner = { formNumber, userId: member.userId, round: equb.currentRound, announcedBy: req.user._id, announcedAt: new Date() };
    await equb.save();

    res.status(200).json({ status: 'success', message: 'Winner announced', data: equb.winner });
  } catch (err) {
    console.error('Announce winner error:', err);
    res.status(500).json({ status: 'error', error: { code: 'equb/announce-failed', message: 'Failed to announce winner' } });
  }
};

// Add New Member
const addMember = async (req, res) => {
  try {
    const {
      fullName,
      formNumber,
      participationType,
      secretNumber,
      phone,
      paidRounds,
    } = req.body;
    const adminUserId = req.user._id;

    // Check if user has admin role
    if (
      !req.member ||
      !["admin", "collector", "judge", "writer"].includes(req.member.role)
    ) {
      return res.status(403).json({
        status: "error",
        error: {
          code: "equb/insufficient-permissions",
          message: "Only admins can add new members",
        },
      });
    }

    // Check if equb is full
    if (req.equb.membersNum >= req.equb.maxMembers) {
      return res.status(400).json({
        status: "error",
        error: {
          code: "equb/full",
          message: "Equb is full",
        },
      });
    }

    // Check if form number is available
    const formNumberTaken = req.equb.members.some(
      (m) => m.formNumber === formNumber
    );
    if (formNumberTaken) {
      return res.status(400).json({
        status: "error",
        error: {
          code: "equb/form-number-taken",
          message: "Form number is already taken",
        },
      });
    }

    // Check if phone number is already a member
    const existingMember = req.equb.members.find((m) => m.phone === phone);
    if (existingMember) {
      return res.status(400).json({
        status: "error",
        error: {
          code: "equb/phone-already-member",
          message: "User with this phone number is already a member",
        },
      });
    }

    // Create new user if doesn't exist
    let user = await User.findOne({ phoneNumber: phone });
    if (!user) {
      const userId = User.generateUserId();
      user = new User({
        userId,
        fullName,
        phoneNumber: phone,
        password: "tempPassword123", // Will be reset by user
        isActive: true,
        isVerified: false,
      });
      await user.save();
    }

    // Add member to equb
    await req.equb.addMember(user._id, {
      name: fullName,
      participationType,
      formNumber,
      role: "member",
    });

    // Add payment history for paid rounds
    if (paidRounds > 0) {
      for (let i = 1; i <= paidRounds; i++) {
        const member = req.equb.members.find(
          (m) => m.userId.toString() === user._id.toString()
        );
        if (member) {
          member.paymentHistory.push({
            roundNumber: i,
            status: "paid",
            amountPaid: req.equb.saving,
            paymentMethod: "cash",
            notes: "Pre-joined payment",
          });
        }
      }
      await req.equb.save();
    }

    // Create notification for new member
    await Notification.createEqubNotification(user._id, req.equb._id, {
      title: "Welcome to Equb",
      message: `You have been added to ${req.equb.name}`,
      priority: "medium",
      actionUrl: `/equb/${req.equb.equbId}`,
    });

    res.status(200).json({
      status: "success",
      message: "Member added successfully",
      data: {
        userId: user.userId,
        memberId: user._id,
      },
    });
  } catch (error) {
    console.error("Add member error:", error);
    res.status(500).json({
      status: "error",
      error: {
        code: "equb/add-member-failed",
        message: "Failed to add member",
      },
    });
  }
};

// Remove Member
const removeMember = async (req, res) => {
  try {
    const { equbId, userId } = req.body;
    const adminUserId = req.user._id;

    // Check if user has admin role
    if (!req.member || !["admin"].includes(req.member.role)) {
      return res.status(403).json({
        status: "error",
        error: {
          code: "equb/insufficient-permissions",
          message: "Only admins can remove members",
        },
      });
    }

    // Check if trying to remove admin
    const memberToRemove = req.equb.members.find(
      (m) => m.userId.toString() === userId
    );
    if (memberToRemove && memberToRemove.role === "admin") {
      return res.status(400).json({
        status: "error",
        error: {
          code: "equb/cannot-remove-admin",
          message: "Cannot remove admin member",
        },
      });
    }

    // Remove member
    await req.equb.removeMember(userId);

    // Create notification for removed member
    await Notification.createEqubNotification(userId, req.equb._id, {
      title: "Removed from Equb",
      message: `You have been removed from ${req.equb.name}`,
      priority: "high",
      actionUrl: `/equb/${req.equb.equbId}`,
    });

    res.status(200).json({
      status: "success",
      message: "Member removed successfully",
    });
  } catch (error) {
    console.error("Remove member error:", error);
    res.status(500).json({
      status: "error",
      error: {
        code: "equb/remove-member-failed",
        message: "Failed to remove member",
      },
    });
  }
};

// Update Member Role
const updateMemberRole = async (req, res) => {
  try {
    const { equbId, userId, role } = req.body;
    const adminUserId = req.user._id;

    // Check if user has admin role
    if (!req.member || !["admin"].includes(req.member.role)) {
      return res.status(403).json({
        status: "error",
        error: {
          code: "equb/insufficient-permissions",
          message: "Only admins can update member roles",
        },
      });
    }

    // Check if trying to update admin role
    const memberToUpdate = req.equb.members.find(
      (m) => m.userId.toString() === userId
    );
    if (memberToUpdate && memberToUpdate.role === "admin") {
      return res.status(400).json({
        status: "error",
        error: {
          code: "equb/cannot-update-admin",
          message: "Cannot update admin member role",
        },
      });
    }

    // Update member role
    await req.equb.updateMemberRole(userId, role);

    // Create notification for member
    await Notification.createEqubNotification(userId, req.equb._id, {
      title: "Role Updated",
      message: `Your role in ${req.equb.name} has been updated to ${role}`,
      priority: "medium",
      actionUrl: `/equb/${req.equb.equbId}`,
    });

    res.status(200).json({
      status: "success",
      message: "Member role updated successfully",
    });
  } catch (error) {
    console.error("Update member role error:", error);
    res.status(500).json({
      status: "error",
      error: {
        code: "equb/update-role-failed",
        message: "Failed to update member role",
      },
    });
  }
};

module.exports = {
  discoverEqubs,
  joinEqub,
  getMyEqubs,
  getEqubDetails,
  addMember,
  removeMember,
  updateMemberRole,
  getEqubMembers,
  getMemberPayments,
  announceWinner
};
