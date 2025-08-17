# Ekub App Backend - Complete API Documentation

## 📋 Table of Contents
1. [Authentication](#authentication)
2. [Equb Creation](#equb-creation)
3. [Equb Management](#equb-management)
4. [Payments](#payments)
5. [Profile Management](#profile-management)
6. [Notifications](#notifications)
7. [Error Handling](#error-handling)
8. [Rate Limiting](#rate-limiting)

---

## 🔐 Authentication

### Base URL: `/api/mobile/auth`

All authentication endpoints are **public** (no token required).

#### 1. User Sign Up
```http
POST /api/mobile/auth/signup
```

**Request Body:**
```json
{
  "fullName": "John Doe",
  "phoneNumber": "+251912345678",
  "password": "SecurePassword123!",
  "confirmPassword": "SecurePassword123!"
}
```

**Success Response (201):**
```json
{
  "status": "success",
  "message": "User registered successfully",
  "data": {
    "user": {
      "userId": "USR123456789",
      "fullName": "John Doe",
      "phoneNumber": "+251912345678",
      "isActive": true,
      "isVerified": false,
      "createdAt": "2024-01-15T10:30:00.000Z"
    },
    "tokens": {
      "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expiresIn": 3600
    }
  }
}
```

#### 2. User Sign In
```http
POST /api/mobile/auth/signin
```

**Request Body:**
```json
{
  "phoneNumber": "+251912345678",
  "password": "SecurePassword123!"
}
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Sign in successful",
  "data": {
    "user": {
      "userId": "USR123456789",
      "fullName": "John Doe",
      "phoneNumber": "+251912345678",
      "profilePicture": "https://example.com/profile.jpg",
      "isActive": true,
      "isVerified": true,
      "lastLogin": "2024-01-15T10:30:00.000Z"
    },
    "tokens": {
      "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expiresIn": 3600
    },
    "joinedEqubs": [
      {
        "equbId": "EQB123456789",
        "participationType": "full",
        "formNumber": 1
      }
    ]
  }
}
```

#### 3. Refresh Token
```http
POST /api/mobile/auth/refresh-token
```

**Request Body:**
```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Token refreshed successfully",
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresIn": 3600
  }
}
```

#### 4. Forgot Password
```http
POST /api/mobile/auth/forgot-password
```

**Request Body:**
```json
{
  "phoneNumber": "+251912345678"
}
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Password reset code sent to your phone number"
}
```

#### 5. Reset Password
```http
POST /api/mobile/auth/reset-password
```

**Request Body:**
```json
{
  "phoneNumber": "+251912345678",
  "resetCode": "123456",
  "newPassword": "NewSecurePassword123!",
  "confirmPassword": "NewSecurePassword123!"
}
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Password reset successfully"
}
```

#### 6. Change Password
```http
PUT /api/mobile/auth/change-password
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "currentPassword": "OldPassword123!",
  "newPassword": "NewPassword123!",
  "confirmPassword": "NewPassword123!"
}
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Password changed successfully"
}
```

#### 7. Sign Out
```http
POST /api/mobile/auth/signout
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Signed out successfully"
}
```

---

## 🏗️ Equb Creation

### Base URL: `/api/mobile/equb-creation`

All endpoints require authentication.

#### 1. Create New Equb
```http
POST /api/mobile/equb-creation/create
```

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: multipart/form-data
```

**Request Body (Form Data):**
```json
{
  "name": "Family Savings Group",
  "numberOfMembers": 10,
  "totalSaving": 50000,
  "duration": 30,
  "level": "beginner",
  "startDate": "2024-02-01",
  "bankAccountDetail": [
    {
      "bankName": "Commercial Bank of Ethiopia",
      "accountNumber": "1000123456789",
      "accountHolderName": "John Doe"
    }
  ],
  "collectorsInfo": [
    {
      "fullName": "Jane Smith",
      "phoneNumber": "+251987654321",
      "formNumber": 2
    }
  ],
  "judgesInfo": [
    {
      "fullName": "Bob Johnson",
      "phoneNumber": "+251976543210",
      "formNumber": 3
    }
  ],
  "writersInfo": [
    {
      "fullName": "Alice Brown",
      "phoneNumber": "+251965432109",
      "formNumber": 4
    }
  ],
  "privacyPolicy": "<file_upload>"
}
```

**Success Response (201):**
```json
{
  "status": "success",
  "message": "Equb created successfully",
  "data": {
    "equb": {
      "equbId": "EQB123456789",
      "name": "Family Savings Group",
      "createdBy": "USR123456789",
      "maxMembers": 10,
      "saving": 50000,
      "perMemberAmount": 5000,
      "roundDuration": 30,
      "level": "beginner",
      "startDate": "2024-02-01T00:00:00.000Z",
      "isActive": true,
      "members": [
        {
          "userId": "USR123456789",
          "name": "John Doe",
          "participationType": "full",
          "formNumber": 1,
          "role": "admin",
          "joinedDate": "2024-01-15T10:30:00.000Z",
          "isActive": true
        }
      ],
      "createdAt": "2024-01-15T10:30:00.000Z"
    }
  }
}
```

#### 2. Get User's Created Equbs
```http
GET /api/mobile/equb-creation/my-created
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "data": {
    "equbs": [
      {
        "equbId": "EQB123456789",
        "name": "Family Savings Group",
        "maxMembers": 10,
        "currentMembers": 5,
        "saving": 50000,
        "perMemberAmount": 5000,
        "roundDuration": 30,
        "level": "beginner",
        "startDate": "2024-02-01T00:00:00.000Z",
        "isActive": true,
        "createdAt": "2024-01-15T10:30:00.000Z"
      }
    ]
  }
}
```

#### 3. Get Equb Creation Details
```http
GET /api/mobile/equb-creation/:equbId
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "data": {
    "equb": {
      "equbId": "EQB123456789",
      "name": "Family Savings Group",
      "createdBy": "USR123456789",
      "maxMembers": 10,
      "saving": 50000,
      "perMemberAmount": 5000,
      "roundDuration": 30,
      "level": "beginner",
      "startDate": "2024-02-01T00:00:00.000Z",
      "bankAccountDetail": [
        {
          "bankName": "Commercial Bank of Ethiopia",
          "accountNumber": "1000123456789",
          "accountHolderName": "John Doe"
        }
      ],
      "members": [
        {
          "userId": "USR123456789",
          "name": "John Doe",
          "participationType": "full",
          "formNumber": 1,
          "role": "admin",
          "joinedDate": "2024-01-15T10:30:00.000Z",
          "isActive": true
        }
      ],
      "isActive": true,
      "createdAt": "2024-01-15T10:30:00.000Z"
    }
  }
}
```

---

## 🏢 Equb Management

### Base URL: `/api/mobile/equbs`

All endpoints require authentication.

#### 1. Discover Available Equbs
```http
GET /api/mobile/equbs/discover-equbs?page=1&limit=10&level=beginner&location=Addis Ababa
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "data": {
    "equbs": [
      {
        "equbId": "EQB123456789",
        "name": "Family Savings Group",
        "maxMembers": 10,
        "currentMembers": 5,
        "saving": 50000,
        "perMemberAmount": 5000,
        "roundDuration": 30,
        "level": "beginner",
        "location": "Addis Ababa",
        "createdBy": {
          "fullName": "John Doe",
          "profilePicture": "https://example.com/profile.jpg"
        },
        "isActive": true,
        "createdAt": "2024-01-15T10:30:00.000Z"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 10,
      "total": 25,
      "pages": 3
    }
  }
}
```

#### 2. Join Equb
```http
POST /api/mobile/equbs/join-equb
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "equbId": "EQB123456789",
  "participationType": "full",
  "formNumber": 6
}
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Successfully joined the equb",
  "data": {
    "equbId": "EQB123456789",
    "participationType": "full",
    "formNumber": 6,
    "joinedDate": "2024-01-15T10:30:00.000Z"
  }
}
```

#### 3. Get User's Equbs
```http
POST /api/mobile/equbs/my-equbs
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "status": "active",
  "role": "admin"
}
```

**Success Response (200):**
```json
{
  "status": "success",
  "data": {
    "equbs": [
      {
        "equbId": "EQB123456789",
        "name": "Family Savings Group",
        "maxMembers": 10,
        "currentMembers": 5,
        "saving": 50000,
        "perMemberAmount": 5000,
        "roundDuration": 30,
        "level": "beginner",
        "role": "admin",
        "participationType": "full",
        "formNumber": 1,
        "joinedDate": "2024-01-15T10:30:00.000Z",
        "isActive": true
      }
    ]
  }
}
```

#### 4. Get Equb Details
```http
GET /api/mobile/equbs/:equbId
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "data": {
    "equb": {
      "equbId": "EQB123456789",
      "name": "Family Savings Group",
      "createdBy": "USR123456789",
      "maxMembers": 10,
      "saving": 50000,
      "perMemberAmount": 5000,
      "roundDuration": 30,
      "level": "beginner",
      "startDate": "2024-02-01T00:00:00.000Z",
      "currentRound": 1,
      "members": [
        {
          "userId": "USR123456789",
          "name": "John Doe",
          "profilePicture": "https://example.com/profile.jpg",
          "participationType": "full",
          "formNumber": 1,
          "role": "admin",
          "joinedDate": "2024-01-15T10:30:00.000Z",
          "isActive": true
        }
      ],
      "bankAccountDetail": [
        {
          "bankName": "Commercial Bank of Ethiopia",
          "accountNumber": "1000123456789",
          "accountHolderName": "John Doe"
        }
      ],
      "isActive": true,
      "createdAt": "2024-01-15T10:30:00.000Z"
    }
  }
}
```

#### 5. Add New Member (Admin Only)
```http
POST /api/mobile/equbs/:equbId/members
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "fullName": "New Member",
  "phoneNumber": "+251912345679",
  "participationType": "full",
  "formNumber": 7,
  "role": "member"
}
```

**Success Response (201):**
```json
{
  "status": "success",
  "message": "Member added successfully",
  "data": {
    "member": {
      "userId": "USR987654321",
      "name": "New Member",
      "participationType": "full",
      "formNumber": 7,
      "role": "member",
      "joinedDate": "2024-01-15T10:30:00.000Z",
      "isActive": true
    }
  }
}
```

#### 6. Remove Member (Admin Only)
```http
DELETE /api/mobile/equbs/:equbId/members/:userId
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Member removed successfully"
}
```

#### 7. Update Member Role (Admin Only)
```http
PUT /api/mobile/equbs/:equbId/members/:userId/role
```

**Headers:**

```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
#### 8. List All Members (Public)
```http
GET /api/mobile/equbs/:equbId/members
```

No authentication required. Returns a list of member names and minimal public info.

Success Response (200):
```json
{
  "status": "success",
  "data": [
    { "name": "John Doe" },
    { "name": "Jane Smith" }
  ]
}
```

#### 9. Get Member Payment History (Public)
```http
GET /api/mobile/equbs/:equbId/members/:userId/payments
```

No authentication required. `userId` can be an app userId (e.g., `UXXXXXXXXX`) or a MongoDB `_id`.

Success Response (200):
```json
{
  "status": "success",
  "data": [
    {
      "paymentMethod": "cash",
      "amount": 5000,
      "date": "2024-01-15T10:30:00.000Z",
      "paidBy": "collector"
    },
    {
      "paymentMethod": "mobile_money",
      "amount": 5000,
      "date": "2024-02-15T10:30:00.000Z",
      "paidBy": "writer"
    }
  ]
}
```

  "role": "collector"
}
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Member role updated successfully",
  "data": {
    "role": "collector"
  }
}
```

---

## 💰 Payments

### Base URL: `/api/mobile/payments`

All endpoints require authentication.

#### 1. Get Payment History
```http
GET /api/mobile/payments/:equbId/payment-history?page=1&limit=10&status=paid
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "data": {
    "payments": [
      {
        "paymentId": "PAY123456789",
        "equbId": "EQB123456789",
        "userId": "USR123456789",
        "userName": "John Doe",
        "round": 1,
        "amount": 5000,
        "status": "paid",
        "paymentDate": "2024-01-15T10:30:00.000Z",
        "collectedBy": "USR987654321",
        "collectionDate": "2024-01-15T10:30:00.000Z",
        "notes": "Payment received on time"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 10,
      "total": 50,
      "pages": 5
    }
  }
}
```

#### 2. Process Payment
```http
POST /api/mobile/payments/process-payment
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json

{
  "equbId": "EQB123456789",  //equb id to payed for
  "userId": "USR123456789", // paid user id
  "currentUserId": "", // current user id to check user role
  "round": 1,   // for which round to pay
  "amount": 5000,  //amount to pay for round
  "paymentMethod": "cash",  //methode
  "notes": "Payment received on time"  //note
}

```

**Success Response (201):**
```json
{
  "status": "success",
  "message": "Payment processed successfully",
  "data": {
    "payment": {
      "paymentId": "PAY123456789",
      "equbId": "EQB123456789",
      "userId": "USR123456789", //paid user id
      "userName": "John Doe",
      "round": 1,
      "amount": 5000,
      "status": "paid",
      "paymentMethod": "cash",
      "paymentDate": "2024-01-15T10:30:00.000Z",
      "collectedBy": "USR987654321",
      "collectionDate": "2024-01-15T10:30:00.000Z",
      "notes": "Payment received on time"
    }
  }
}
```

#### 3. Get Unpaid Members
```http
GET /api/mobile/payments/:equbId/unpaid-members?round=1
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "data": {
    "unpaidMembers": [
      {
        "userId": "USR123456789",
        "name": "John Doe",
        "phoneNumber": "+251912345678",
        "formNumber": 1,
        "round": 1,
        "amount": 5000,
        "dueDate": "2024-01-20T00:00:00.000Z",
        "daysOverdue": 5
      }
    ],
    "summary": {
      "totalMembers": 10,
      "paidMembers": 7,
      "unpaidMembers": 3,
      "totalAmount": 15000
    }
  }
}
```

#### 4. Get Payment Summary
```http
GET /api/mobile/payments/:equbId/payment-summary
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "data": {
    "summary": {
      "totalMembers": 10,
      "currentRound": 1,
      "totalRounds": 10,
      "perMemberAmount": 5000,
      "totalSaving": 50000,
      "collectedAmount": 35000,
      "remainingAmount": 15000,
      "paymentRate": 70,
      "roundsCompleted": 7,
      "roundsRemaining": 3
    },
    "roundStats": [
      {
        "round": 1,
        "paidMembers": 10,
        "unpaidMembers": 0,
        "collectedAmount": 50000,
        "status": "completed"
      }
    ]
  }
}
```

#### 5. Mark Payment as Unpaid
```http
PUT /api/mobile/payments/:paymentId/mark-unpaid
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "reason": "Payment verification failed"
}
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Payment marked as unpaid",
  "data": {
    "paymentId": "PAY123456789",
    "status": "unpaid",
    "reason": "Payment verification failed"
  }
}
```

#### 6. Cancel Payment
```http
PUT /api/mobile/payments/:paymentId/cancel
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "reason": "Payment cancelled by user"
}
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Payment cancelled successfully",
  "data": {
    "paymentId": "PAY123456789",
    "status": "cancelled",
    "reason": "Payment cancelled by user"
  }
}
```

---

## 👤 Profile Management

### Base URL: `/api/mobile/profile`

All endpoints require authentication.

#### 1. Get User Profile
```http
GET /api/mobile/profile
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "data": {
    "user": {
      "userId": "USR123456789",
      "fullName": "John Doe",
      "phoneNumber": "+251912345678",
      "email": "john.doe@example.com",
      "profilePicture": "https://example.com/profile.jpg",
      "dateOfBirth": "1990-01-01",
      "gender": "male",
      "address": {
        "street": "Bole Road",
        "city": "Addis Ababa",
        "state": "Addis Ababa",
        "country": "Ethiopia",
        "postalCode": "1000"
      },
      "isActive": true,
      "isVerified": true,
      "createdAt": "2024-01-15T10:30:00.000Z",
      "lastLogin": "2024-01-15T10:30:00.000Z"
    }
  }
}
```

#### 2. Update User Profile
```http
PUT /api/mobile/profile
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "fullName": "John Smith Doe",
  "email": "john.smith@example.com",
  "dateOfBirth": "1990-01-01",
  "gender": "male",
  "address": {
    "street": "Bole Road",
    "city": "Addis Ababa",
    "state": "Addis Ababa",
    "country": "Ethiopia",
    "postalCode": "1000"
  }
}
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Profile updated successfully",
  "data": {
    "user": {
      "userId": "USR123456789",
      "fullName": "John Smith Doe",
      "phoneNumber": "+251912345678",
      "email": "john.smith@example.com",
      "profilePicture": "https://example.com/profile.jpg",
      "dateOfBirth": "1990-01-01",
      "gender": "male",
      "address": {
        "street": "Bole Road",
        "city": "Addis Ababa",
        "state": "Addis Ababa",
        "country": "Ethiopia",
        "postalCode": "1000"
      },
      "isActive": true,
      "isVerified": true,
      "updatedAt": "2024-01-15T10:30:00.000Z"
    }
  }
}
```

#### 3. Upload Profile Picture
```http
POST /api/mobile/profile/profile-picture
```

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: multipart/form-data
```

**Request Body (Form Data):**
```json
{
  "profilePicture": "<file_upload>"
}
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Profile picture uploaded successfully",
  "data": {
    "profilePicture": "https://example.com/uploads/profile-pictures/profile-123456789.jpg"
  }
}
```

#### 4. Delete Profile Picture
```http
DELETE /api/mobile/profile/profile-picture
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Profile picture deleted successfully"
}
```

#### 5. Get User Statistics
```http
GET /api/mobile/profile/statistics
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "data": {
    "statistics": {
      "totalEqubs": 5,
      "activeEqubs": 3,
      "totalSavings": 150000,
      "totalPayments": 25,
      "onTimePayments": 22,
      "latePayments": 3,
      "paymentRate": 88,
      "memberSince": "2024-01-15T10:30:00.000Z",
      "lastPayment": "2024-01-15T10:30:00.000Z"
    }
  }
}
```

#### 6. Deactivate Account
```http
POST /api/mobile/profile/deactivate
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "reason": "Taking a break from equbs"
}
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Account deactivated successfully"
}
```

#### 7. Reactivate Account
```http
POST /api/mobile/profile/reactivate
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Account reactivated successfully"
}
```

---

## 🔔 Notifications

### Base URL: `/api/mobile/notifications`

All endpoints require authentication.

#### 1. Get Notifications
```http
GET /api/mobile/notifications?page=1&limit=10&type=payment&read=false
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "data": {
    "notifications": [
      {
        "notificationId": "NOT123456789",
        "title": "Payment Due",
        "message": "Your payment of 5000 ETB is due for Equb Family Savings Group",
        "type": "payment",
        "priority": "high",
        "read": false,
        "data": {
          "equbId": "EQB123456789",
          "amount": 5000,
          "dueDate": "2024-01-20T00:00:00.000Z"
        },
        "createdAt": "2024-01-15T10:30:00.000Z"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 10,
      "total": 25,
      "pages": 3
    }
  }
}
```

#### 2. Get Unread Count
```http
GET /api/mobile/notifications/unread-count
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "data": {
    "unreadCount": 5,
    "byType": {
      "payment": 3,
      "equb": 1,
      "system": 1
    }
  }
}
```

#### 3. Mark Notification as Read
```http
PUT /api/mobile/notifications/:notificationId/read
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Notification marked as read"
}
```

#### 4. Mark All Notifications as Read
```http
PUT /api/mobile/notifications/mark-all-read
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "All notifications marked as read",
  "data": {
    "updatedCount": 5
  }
}
```

#### 5. Delete Notification
```http
DELETE /api/mobile/notifications/:notificationId
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Notification deleted successfully"
}
```

#### 6. Delete All Notifications
```http
DELETE /api/mobile/notifications
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "All notifications deleted successfully",
  "data": {
    "deletedCount": 25
  }
}
```

#### 7. Get Notification Settings
```http
GET /api/mobile/notifications/settings
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "data": {
    "settings": {
      "pushNotifications": true,
      "emailNotifications": false,
      "smsNotifications": true,
      "paymentReminders": true,
      "equbUpdates": true,
      "systemAnnouncements": false,
      "quietHours": {
        "enabled": true,
        "start": "22:00",
        "end": "08:00"
      }
    }
  }
}
```

#### 8. Update Notification Settings
```http
PUT /api/mobile/notifications/settings
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "pushNotifications": true,
  "emailNotifications": false,
  "smsNotifications": true,
  "paymentReminders": true,
  "equbUpdates": true,
  "systemAnnouncements": false,
  "quietHours": {
    "enabled": true,
    "start": "22:00",
    "end": "08:00"
  }
}
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Notification settings updated successfully"
}
```

#### 9. Send Test Notification
```http
POST /api/mobile/notifications/test
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Test notification sent successfully"
}
```

#### 10. Bulk Actions
```http
POST /api/mobile/notifications/bulk-actions
```

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "action": "mark-read",
  "notificationIds": ["NOT123456789", "NOT987654321"],
  "filters": {
    "type": "payment",
    "read": false
  }
}
```

**Success Response (200):**
```json
{
  "status": "success",
  "message": "Bulk action completed successfully",
  "data": {
    "affectedCount": 2
  }
}
```

---

## ❌ Error Handling

### Standard Error Response Format

All error responses follow this format:

```json
{
  "status": "error",
  "error": {
    "code": "error/type",
    "message": "Human-readable error message"
  }
}
```

### Common Error Codes

#### Authentication Errors (401)
- `auth/no-token` - Access token is required
- `auth/invalid-token` - Invalid or expired token
- `auth/token-expired` - Token has expired
- `auth/user-not-found` - User not found or inactive
- `auth/invalid-credentials` - Invalid phone number or password
- `auth/account-disabled` - Account is disabled

#### Authorization Errors (403)
- `auth/insufficient-permissions` - User doesn't have required permissions
- `equb/not-member` - User is not a member of this equb
- `equb/not-admin` - User is not an admin of this equb

#### Validation Errors (422)
- `validation/required-field` - Required field is missing
- `validation/invalid-format` - Invalid data format
- `validation/phone-number` - Invalid phone number format
- `validation/password-strength` - Password doesn't meet requirements

#### Resource Errors (404)
- `equb/not-found` - Equb not found
- `user/not-found` - User not found
- `payment/not-found` - Payment not found
- `notification/not-found` - Notification not found

#### Business Logic Errors (400)
- `equb-creation/already-exists` - User already has an active equb creation
- `equb/member-exists` - User is already a member
- `equb/max-members-reached` - Equb has reached maximum members
- `payment/already-paid` - Payment has already been processed
- `payment/invalid-amount` - Invalid payment amount

#### Server Errors (500)
- `server/internal-error` - Internal server error
- `server/database-error` - Database operation failed
- `server/external-service-error` - External service error

### Example Error Responses

#### 401 Unauthorized
```json
{
  "status": "error",
  "error": {
    "code": "auth/invalid-token",
    "message": "Invalid or expired token"
  }
}
```

#### 422 Validation Error
```json
{
  "status": "error",
  "error": {
    "code": "validation/required-field",
    "message": "Phone number is required",
    "field": "phoneNumber"
  }
}
```

#### 404 Not Found
```json
{
  "status": "error",
  "error": {
    "code": "equb/not-found",
    "message": "Equb not found"
  }
}
```

---

## 🚦 Rate Limiting

The API implements rate limiting to prevent abuse:

### Rate Limits by Endpoint Type

- **Authentication endpoints**: 5 requests per minute
- **Payment endpoints**: 10 requests per minute
- **Equb creation endpoints**: 3 requests per minute
- **General endpoints**: 60 requests per minute

### Rate Limit Response

When rate limit is exceeded:

```json
{
  "status": "error",
  "error": {
    "code": "rate-limit/exceeded",
    "message": "Too many requests from this IP, please try again later."
  }
}
```

### Headers

Rate limit information is included in response headers:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1642234567
```
