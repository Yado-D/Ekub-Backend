const Joi = require('joi');

// Common validation schemas
const commonSchemas = {
  phoneNumber: Joi.string()
    .pattern(/^\+[1-9]\d{1,14}$/)
    .message('Phone number must be in international format (e.g., +251911234567)'),
  
  password: Joi.string()
    .min(6)
    .max(128)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .message('Password must be at least 6 characters and contain at least one uppercase letter, one lowercase letter, and one number'),
  
  email: Joi.string()
    .email()
    .message('Please provide a valid email address'),
  
  userId: Joi.string()
    .pattern(/^U[A-Z0-9]{9}$/)
    .message('User ID must be in format U followed by 9 alphanumeric characters'),
  
  equbId: Joi.string()
    .pattern(/^E[A-Z0-9]{9}$/)
    .message('Equb ID must be in format E followed by 9 alphanumeric characters'),
  
  paymentId: Joi.string()
    .pattern(/^P[A-Z0-9]{9}$/)
    .message('Payment ID must be in format P followed by 9 alphanumeric characters'),
  
  notificationId: Joi.string()
    .pattern(/^N[A-Z0-9]{9}$/)
    .message('Notification ID must be in format N followed by 9 alphanumeric characters'),
  
  pagination: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20)
  })
};

// Authentication validation schemas
const authSchemas = {
  signIn: Joi.object({
    phoneNumber: commonSchemas.phoneNumber.required(),
    password: commonSchemas.password.required()
  }),
  
  signUp: Joi.object({
    fullName: Joi.string()
      .min(2)
      .max(100)
      .pattern(/^[a-zA-Z\s]+$/)
      .message('Full name must contain only letters and spaces')
      .required(),
    referralId: Joi.string().optional(),
    phoneNumber: commonSchemas.phoneNumber.required(),
    password: commonSchemas.password.required(),
    confirmPassword: Joi.string()
      .valid(Joi.ref('password'))
      .required()
      .messages({
        'any.only': 'Passwords do not match'
      }),
    email: commonSchemas.email.optional()
  }),
  
  refreshToken: Joi.object({
    refreshToken: Joi.string().required()
  }),
  
  forgotPassword: Joi.object({
    phoneNumber: commonSchemas.phoneNumber.required()
  }),
  
  resetPassword: Joi.object({
    phoneNumber: commonSchemas.phoneNumber.required(),
    newPassword: commonSchemas.password.required(),
    confirmPassword: Joi.string()
      .valid(Joi.ref('newPassword'))
      .required()
      .messages({
        'any.only': 'Passwords do not match'
      })
  }),
  
  changePassword: Joi.object({
    currentPassword: Joi.string().required(),
    newPassword: commonSchemas.password.required(),
    confirmPassword: Joi.string()
      .valid(Joi.ref('newPassword'))
      .required()
      .messages({
        'any.only': 'Passwords do not match'
      })
  })
};

// Equb validation schemas
const equbSchemas = {
  discoverEqubs: Joi.object({
    type: Joi.string().valid('public', 'private', 'all').default('all'),
    roundDuration: Joi.string().valid('daily', 'weekly', 'monthly', 'all').default('all'),
    savingAmount: Joi.number().positive().optional(),
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(10)
  }),
  
  joinEqub: Joi.object({
    equbId: commonSchemas.equbId.required(),
    participationType: Joi.string().valid('full', 'half').required(),
    formNumber: Joi.number().integer().min(1).required(),
    secretNumber: Joi.string().length(6).optional()
  }),
     
  getMyEqubs: Joi.object({
    userEkubId: Joi.array().items(commonSchemas.equbId).optional()
  }),
      
  addMember: Joi.object({
    fullName: Joi.string()
      .min(2)
      .max(100)
      .pattern(/^[a-zA-Z\s]+$/)
      .message('Full name must contain only letters and spaces')
      .required(),
    formNumber: Joi.number().integer().min(1).required(),
  participationType: Joi.string().valid('full', 'half', 'quarter').required(),
    secretNumber: Joi.string().length(6).optional(),
  secretKey: Joi.string().length(6).optional(),
    phone: commonSchemas.phoneNumber.required(),
    paidRounds: Joi.number().integer().min(0).default(0)
  }),
  
  updateMemberRole: Joi.object({
    equbId: commonSchemas.equbId.required(),
    userId: commonSchemas.userId.required(),
    role: Joi.string().valid('member', 'collector', 'judge', 'writer', 'admin').required()
  }),

  createEqub: Joi.object({
    name: Joi.string().min(3).max(100).required(),
    numberOfMembers: Joi.number().min(5).max(500).required(),
    totalSaving: Joi.number().min(1000).max(500000).required(),
    duration: Joi.string().valid('daily', 'weekly', 'monthly').required(),
    level: Joi.string().valid('old', 'new').required(),
    startDate: Joi.date().required(),
    bankAccountDetail: Joi.array().items(
      Joi.object({
        bankName: Joi.string().min(2).max(100).required(),
        accountNumber: Joi.string().min(5).max(50).required(),
        accountHolder: Joi.string().min(2).max(100).required()
      })
    ).max(5).optional(),
    collectorsInfo: Joi.array().items(
      Joi.object({
        fullName: Joi.string().min(2).max(100).required(),
        phoneNumber: Joi.string().pattern(/^\+?[1-9]\d{1,14}$/).required(),
        formNumber: Joi.string().optional(),
        password: Joi.string().min(6).max(128).optional()
      })
    ).max(10).optional(),
    judgesInfo: Joi.array().items(
      Joi.object({
        fullName: Joi.string().min(2).max(100).required(),
        phoneNumber: Joi.string().pattern(/^\+?[1-9]\d{1,14}$/).required(),
        formNumber: Joi.string().optional(),
        password: Joi.string().min(6).max(128).optional()
      })
    ).max(5).optional(),
    writersInfo: Joi.array().items(
      Joi.object({
        fullName: Joi.string().min(2).max(100).required(),
        phoneNumber: Joi.string().pattern(/^\+?[1-9]\d{1,14}$/).required(),
        formNumber: Joi.string().optional(),
        password: Joi.string().min(6).max(128).optional()
      })
    ).max(5).optional()
  })
};

// Payment validation schemas
const paymentSchemas = {
  paymentHistory: Joi.object({
    userId: commonSchemas.userId.optional(),
    status: Joi.string().valid('paid', 'unpaid', 'all').default('all'),
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20)
  }),
  
  processPayment: Joi.object({
    equbId: commonSchemas.equbId.required(),
    // allow processor roles
    role: Joi.string().valid('collector', 'admin', 'judge', 'writer').required(),
    // accept either app userId (U...) or a Mongo ObjectId
    userId: Joi.alternatives()
      .try(
        commonSchemas.userId,
        Joi.string().pattern(/^[a-fA-F0-9]{24}$/).message('userId must be either app userId (U...) or a Mongo ObjectId')
      )
      .required(),
    roundNumber: Joi.number().integer().min(1).required(),
    paymentMethod: Joi.string().valid('cash', 'bank', 'mobile_money').required(),
    amount: Joi.number().positive().required(),
    notes: Joi.string().max(500).optional()
  }),
  
  unpaidMembers: Joi.object({
    roundNumber: Joi.number().integer().min(1).optional(),
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20)
  })
};

// Profile validation schemas
const profileSchemas = {
  updateProfile: Joi.object({
    fullName: Joi.string()
      .min(2)
      .max(100)
      .pattern(/^[a-zA-Z\s]+$/)
      .message('Full name must contain only letters and spaces')
      .optional(),
    email: commonSchemas.email.optional(),
    dateOfBirth: Joi.date().max('now').optional(),
    gender: Joi.string().valid('male', 'female', 'other').optional(),
    address: Joi.object({
      city: Joi.string().trim().optional(),
      subCity: Joi.string().trim().optional(),
      woreda: Joi.string().trim().optional(),
      houseNumber: Joi.string().trim().optional()
    }).optional(),
    bankDetails: Joi.array().items(
      Joi.object({
        bankName: Joi.string().trim().required(),
        accountNumber: Joi.string().trim().required(),
        accountHolder: Joi.string().trim().required()
      })
    ).optional()
  })
};

// Notification validation schemas
const notificationSchemas = {
  getNotifications: Joi.object({
    type: Joi.string().valid('all', 'payment', 'equb', 'system').default('all'),
    read: Joi.string().valid('true', 'false', 'all').default('all'),
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20)
  })
};

// Validation middleware factory
const validate = (schema, property = 'body') => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req[property], {
      abortEarly: false,
      stripUnknown: true
    });

    if (error) {
      const errorDetails = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message
      }));

      return res.status(422).json({
        status: "error",
        error: {
          code: "validation/error",
          message: "Validation failed",
          details: errorDetails
        }
      });
    }

    // Replace request data with validated data
    req[property] = value;
    next();
  };
};

// Export all schemas and validation middleware
module.exports = {
  // Schemas
  commonSchemas,
  authSchemas,
  equbSchemas,
  paymentSchemas,
  profileSchemas,
  notificationSchemas,
  
  // Validation middleware
  validate,
  
  // Pre-built validation middleware
  validateSignIn: validate(authSchemas.signIn),
  validateSignUp: validate(authSchemas.signUp),
  validateRefreshToken: validate(authSchemas.refreshToken),
  validateForgotPassword: validate(authSchemas.forgotPassword),
  validateResetPassword: validate(authSchemas.resetPassword),
  validateChangePassword: validate(authSchemas.changePassword),
  
  validateDiscoverEqubs: validate(equbSchemas.discoverEqubs, 'query'),
  validateJoinEqub: validate(equbSchemas.joinEqub),
  validateGetMyEqubs: validate(equbSchemas.getMyEqubs),
  validateAddMember: validate(equbSchemas.addMember),
  validateUpdateMemberRole: validate(equbSchemas.updateMemberRole),
  validateEqubCreation: validate(equbSchemas.createEqub),
  
  validatePaymentHistory: validate(paymentSchemas.paymentHistory, 'query'),
  validateProcessPayment: validate(paymentSchemas.processPayment),
  validateUnpaidMembers: validate(paymentSchemas.unpaidMembers, 'query'),
  
  validateUpdateProfile: validate(profileSchemas.updateProfile),
  validateGetNotifications: validate(notificationSchemas.getNotifications, 'query')
}; 