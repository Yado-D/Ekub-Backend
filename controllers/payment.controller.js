const Payment = require('../models/Payment');
const Equb = require('../models/Equb');
const User = require('../models/User');
const Notification = require('../models/Notification');

// Get Payment History
const getPaymentHistory = async (req, res) => {
  try {
    const { equbId } = req.params;
    const { userId, status, page = 1, limit = 20 } = req.query;
    const currentUserId = req.user ? req.user._id : null;

    // If authenticated, prefer membership-restricted view; if unauthenticated,
    // allow public access but require userId query when requesting member-specific history.
    let equb = null;
    if (currentUserId) {
      equb = await Equb.findOne({ equbId, 'members.userId': currentUserId });
      if (!equb) {
        return res.status(403).json({
          status: "error",
          error: {
            code: "equb/not-member",
            message: "You are not a member of this equb"
          }
        });
      }
    } else {
      // public access: fetch equb (read-only) but don't require membership
      equb = await Equb.findOne({ equbId });
      if (!equb) {
        return res.status(404).json({ status: 'error', error: { code: 'equb/not-found', message: 'Equb not found' } });
      }
      // require query userId when requesting specific user's history while unauthenticated
      if (!userId) {
        return res.status(400).json({
          status: 'error',
          error: { code: 'validation/missing-field', message: 'userId query parameter is required for public payment history' }
        });
      }
    }

    // Build query
  const query = { equbId: equb._id };
  if (userId) query.userId = userId;
    if (status && status !== 'all') query.status = status;

    // Get total count
    const total = await Payment.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

  // Get payments with pagination
    const payments = await Payment.find(query)
      .populate('userId', 'fullName')
      .populate('equbId', 'name equbId')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    // Format payment data
    const formattedPayments = payments.map(payment => ({
      paymentId: payment.paymentId,
      roundNumber: payment.roundNumber,
      date: payment.date,
      status: payment.status,
      amountPaid: payment.amountPaid,
      paymentMethod: payment.paymentMethod,
  userId: payment.userId._id,
  userName: payment.userId.fullName,
      formNumber: equb.members.find(m => m.userId.toString() === payment.userId._id.toString())?.formNumber || 0,
      participationType: equb.members.find(m => m.userId.toString() === payment.userId._id.toString())?.participationType || 'full'
    }));

    // Calculate summary
  const allPayments = await Payment.find({ equbId: equb._id });
    const summary = {
      totalPaid: allPayments
        .filter(p => p.status === 'paid')
        .reduce((sum, p) => sum + p.amountPaid, 0),
      totalUnpaid: allPayments
        .filter(p => p.status === 'unpaid')
        .reduce((sum, p) => sum + p.amount, 0),
      totalMembers: equb.membersNum,
      paidMembers: allPayments.filter(p => p.status === 'paid').length,
      unpaidMembers: allPayments.filter(p => p.status === 'unpaid').length
    };

    res.status(200).json({
      status: "success",
      data: {
        payments: formattedPayments,
        summary,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1
        }
      }
    });

  } catch (error) {
    console.error('Get payment history error:', error);
    res.status(500).json({
      status: "error",
      error: {
        code: "payment/history-failed",
        message: "Failed to get payment history"
      }
    });
  }
};

// Process Payment
const processPayment = async (req, res) => {
  try {
  const { equbId, role, userId, roundNumber, paymentMethod, amount, notes } = req.body;
  const processedBy = req.user._id;

  // Prefer role from middleware (req.member) if present, otherwise fall back to body.role
  const processorRole = req.member?.role || role;

  // Check if user has permission to process payments
    if (!['collector', 'judge', 'writer'].includes(processorRole)) {
      return res.status(403).json({
        status: "error",
        error: {
          code: "payment/insufficient-permissions",
          message: "Only collectors, judges, or writers can process payments"
        }
      });
    }

    // Find the equb
  const equb = await Equb.findOne({ equbId });
    if (!equb) {
      return res.status(404).json({
        status: "error",
        error: {
          code: "equb/not-found",
          message: "Equb not found"
        }
      });
    }

    // Resolve target user either by app userId or Mongo id
    let targetUser = null;
    if (/^U[A-Z0-9]{9}$/.test(userId)) targetUser = await User.findOne({ userId });
    else targetUser = await User.findById(userId);

    if (!targetUser) {
      return res.status(404).json({ status: 'error', error: { code: 'equb/member-not-found', message: 'Member not found in this equb' } });
    }

    const member = equb.members.find(m => m.userId.toString() === targetUser._id.toString());
    if (!member) {
      return res.status(404).json({
        status: "error",
        error: {
          code: "equb/member-not-found",
          message: "Member not found in this equb"
        }
      });
    }

    // Check if payment already exists for this round
    let payment = await Payment.findOne({
      equbId: equb._id,
      userId: targetUser._id,
      roundNumber
    });

    if (payment) {
      // Update existing payment
      payment.status = 'paid';
      payment.amountPaid = amount;
      payment.paymentMethod = paymentMethod;
      payment.notes = notes;
      payment.processedBy = processedBy;
      payment.processedAt = new Date();
      payment.paidDate = new Date();
      payment.transactionId = Payment.generateTransactionId();
    } else {
      // Create new payment
      payment = new Payment({
        paymentId: Payment.generatePaymentId(),
        equbId: equb._id,
        userId: targetUser._id,
        roundNumber,
        amount: equb.saving,
        status: 'paid',
        paymentMethod,
        notes,
        processedBy,
        processedAt: new Date(),
        paidDate: new Date(),
        transactionId: Payment.generateTransactionId(),
        dueDate: new Date() // Calculate based on round duration
      });
    }

    await payment.save();

    // Update equb member payment history
  await equb.processPayment(targetUser._id, roundNumber, {
      status: 'paid',
      amount: amount,
      paymentMethod,
      notes
    });

    // Create notification for member
  await Notification.createEqubNotification(targetUser._id, equb._id, {
      title: 'Payment Processed',
      message: `Your payment of ${amount} for round ${roundNumber} has been processed successfully`,
      priority: 'medium',
      actionUrl: `/equb/${equb.equbId}/payment-history`
    });

    res.status(200).json({
      status: "success",
      message: "Payment processed successfully",
      data: {
        paymentId: payment.paymentId,
        transactionId: payment.transactionId,
        processedAt: payment.processedAt
      }
    });

  } catch (error) {
    console.error('Process payment error:', error);
    res.status(500).json({
      status: "error",
      error: {
        code: "payment/process-failed",
        message: "Failed to process payment"
      }
    });
  }
};

// Get Unpaid Members
const getUnpaidMembers = async (req, res) => {
  try {
    const { equbId } = req.params;
    const { roundNumber, page = 1, limit = 20 } = req.query;
    const currentUserId = req.user ? req.user._id : null;

    // If authenticated, require membership; otherwise allow public read-only access
    let equb = null;
    if (currentUserId) {
      equb = await Equb.findOne({ equbId, 'members.userId': currentUserId });
      if (!equb) {
        return res.status(403).json({
          status: "error",
          error: {
            code: "equb/not-member",
            message: "You are not a member of this equb"
          }
        });
      }
    } else {
      equb = await Equb.findOne({ equbId });
      if (!equb) {
        return res.status(404).json({ status: 'error', error: { code: 'equb/not-found', message: 'Equb not found' } });
      }
    }

    // Determine which round to check
    const targetRound = roundNumber || equb.currentRound;

    // Get unpaid members for the target round
    const unpaidMembers = [];
    
  for (const member of equb.members) {
      if (!member.isActive) continue;

      const roundPayment = member.paymentHistory.find(p => p.roundNumber === targetRound);
      if (!roundPayment || roundPayment.status !== 'paid') {
        // Find all unpaid rounds for this member
        const unpaidRounds = [];
        for (let i = 1; i <= targetRound; i++) {
          const payment = member.paymentHistory.find(p => p.roundNumber === i);
          if (!payment || payment.status !== 'paid') {
            unpaidRounds.push(i);
          }
        }

        // Calculate total unpaid amount
        const totalUnpaid = unpaidRounds.length * equb.saving;

        // Get last payment date
        const lastPayment = member.paymentHistory
          .filter(p => p.status === 'paid')
          .sort((a, b) => new Date(b.date) - new Date(a.date))[0];

        unpaidMembers.push({
          userId: member.userId,
          fullName: member.name,
          phone: member.phone || null,
          participationType: member.participationType,
          formNumber: member.formNumber,
          unpaidRounds,
          totalUnpaid,
          lastPaymentDate: lastPayment ? lastPayment.date : null
        });
      }
    }

    // Apply pagination
    const total = unpaidMembers.length;
    const totalPages = Math.ceil(total / limit);
    const paginatedMembers = unpaidMembers
      .sort((a, b) => b.totalUnpaid - a.totalUnpaid)
      .slice((page - 1) * limit, page * limit);

    // Calculate summary
    const summary = {
      totalUnpaidMembers: total,
      totalUnpaidAmount: unpaidMembers.reduce((sum, m) => sum + m.totalUnpaid, 0)
    };

    res.status(200).json({
      status: "success",
      data: {
        unpaidMembers: paginatedMembers,
        summary,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1
        }
      }
    });

  } catch (error) {
    console.error('Get unpaid members error:', error);
    res.status(500).json({
      status: "error",
      error: {
        code: "payment/unpaid-members-failed",
        message: "Failed to get unpaid members"
      }
    });
  }
};

// Get Payment Summary
const getPaymentSummary = async (req, res) => {
  try {
    const { equbId } = req.params;
    const currentUserId = req.user._id;

    // Check if user is a member of this equb
    const equb = await Equb.findOne({ equbId, 'members.userId': currentUserId });
    if (!equb) {
      return res.status(403).json({
        status: "error",
        error: {
          code: "equb/not-member",
          message: "You are not a member of this equb"
        }
      });
    }

    // Get payment summary using equb method
    const summary = equb.getPaymentSummary();

    // Calculate next payment date based on round duration
    let nextPaymentDate = new Date(equb.startDate);
    if (equb.roundDuration === 'weekly') {
      nextPaymentDate.setDate(nextPaymentDate.getDate() + (equb.currentRound * 7));
    } else if (equb.roundDuration === 'monthly') {
      nextPaymentDate.setMonth(nextPaymentDate.getMonth() + equb.currentRound);
    } else if (equb.roundDuration === 'daily') {
      nextPaymentDate.setDate(nextPaymentDate.getDate() + equb.currentRound);
    }

    summary.nextPaymentDate = nextPaymentDate;

    res.status(200).json({
      status: "success",
      data: summary
    });

  } catch (error) {
    console.error('Get payment summary error:', error);
    res.status(500).json({
      status: "error",
      error: {
        code: "payment/summary-failed",
        message: "Failed to get payment summary"
      }
    });
  }
};

// Mark Payment as Unpaid
const markPaymentAsUnpaid = async (req, res) => {
  try {
    const { paymentId } = req.params;
    const currentUserId = req.user._id;

    // Find the payment
    const payment = await Payment.findOne({ paymentId });
    if (!payment) {
      return res.status(404).json({
        status: "error",
        error: {
          code: "payment/not-found",
          message: "Payment not found"
        }
      });
    }

    // Check if user has permission (collector or admin)
    const equb = await Equb.findById(payment.equbId);
    const member = equb.members.find(m => m.userId.toString() === currentUserId.toString());
    
    if (!member || !['collector', 'admin'].includes(member.role)) {
      return res.status(403).json({
        status: "error",
        error: {
          code: "payment/insufficient-permissions",
          message: "Only collectors and admins can modify payments"
        }
      });
    }

    // Mark payment as unpaid
    await payment.markAsUnpaid();

    // Update equb member payment history
    await equb.processPayment(payment.userId, payment.roundNumber, {
      status: 'unpaid',
      amount: 0,
      paymentMethod: 'cash',
      notes: 'Payment marked as unpaid'
    });

    // Create notification for member
    await Notification.createEqubNotification(payment.userId, equb._id, {
      title: 'Payment Status Changed',
      message: `Your payment for round ${payment.roundNumber} has been marked as unpaid`,
      priority: 'high',
      actionUrl: `/equb/${equb.equbId}/payment-history`
    });

    res.status(200).json({
      status: "success",
      message: "Payment marked as unpaid successfully"
    });

  } catch (error) {
    console.error('Mark payment as unpaid error:', error);
    res.status(500).json({
      status: "error",
      error: {
        code: "payment/mark-unpaid-failed",
        message: "Failed to mark payment as unpaid"
      }
    });
  }
};

// Cancel Payment
const cancelPayment = async (req, res) => {
  try {
    const { paymentId } = req.params;
    const { reason } = req.body;
    const currentUserId = req.user._id;

    // Find the payment
    const payment = await Payment.findOne({ paymentId });
    if (!payment) {
      return res.status(404).json({
        status: "error",
        error: {
          code: "payment/not-found",
          message: "Payment not found"
        }
      });
    }

    // Check if user has permission (collector or admin)
    const equb = await Equb.findById(payment.equbId);
    const member = equb.members.find(m => m.userId.toString() === currentUserId.toString());
    
    if (!member || !['collector', 'admin'].includes(member.role)) {
      return res.status(403).json({
        status: "error",
        error: {
          code: "payment/insufficient-permissions",
          message: "Only collectors and admins can cancel payments"
        }
      });
    }

    // Cancel payment
    await payment.cancelPayment(reason);

    // Update equb member payment history
    await equb.processPayment(payment.userId, payment.roundNumber, {
      status: 'cancelled',
      amount: 0,
      paymentMethod: 'cash',
      notes: reason || 'Payment cancelled'
    });

    // Create notification for member
    await Notification.createEqubNotification(payment.userId, equb._id, {
      title: 'Payment Cancelled',
      message: `Your payment for round ${payment.roundNumber} has been cancelled: ${reason || 'No reason provided'}`,
      priority: 'high',
      actionUrl: `/equb/${equb.equbId}/payment-history`
    });

    res.status(200).json({
      status: "success",
      message: "Payment cancelled successfully"
    });

  } catch (error) {
    console.error('Cancel payment error:', error);
    res.status(500).json({
      status: "error",
      error: {
        code: "payment/cancel-failed",
        message: "Failed to cancel payment"
      }
    });
  }
};

module.exports = {
  getPaymentHistory,
  processPayment,
  getUnpaidMembers,
  getPaymentSummary,
  markPaymentAsUnpaid,
  cancelPayment
}; 