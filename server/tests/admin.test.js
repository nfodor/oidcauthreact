const request = require('supertest');
const app = require('../server');
const { User } = require('../models/user');

describe('Admin Endpoints', () => {
  let adminToken, userToken, userId, adminId;

  beforeEach(async () => {
    // Create admin user
    const adminRes = await request(app)
      .post('/auth/register')
      .send({
        email: 'admin@example.com',
        password: 'password123',
        name: 'Admin User'
      });

    // Create regular user
    const userRes = await request(app)
      .post('/auth/register')
      .send({
        email: 'user@example.com',
        password: 'password123',
        name: 'Regular User'
      });

    // Set admin role directly in the database
    adminId = adminRes.body.user._id;
    await User.findByIdAndUpdate(adminId, { role: 'admin' });
    
    // Get updated admin user with admin role
    const updatedAdmin = await User.findById(adminId);
    
    // Generate new token with admin role
    const jwt = require('jsonwebtoken');
    adminToken = jwt.sign(
      { id: adminId, role: updatedAdmin.role },
      process.env.JWT_SECRET || 'test_jwt_secret',
      { expiresIn: '15m' }
    );

    userId = userRes.body.user._id;
    userToken = userRes.headers['set-cookie']
      .find(cookie => cookie.startsWith('accessToken='))
      .split(';')[0]
      .split('=')[1];
  });

  describe('PUT /admin/users/:id/role', () => {
    it('should allow admin to update user role', async () => {
      const res = await request(app)
        .put(`/admin/users/${userId}/role`)
        .set('Cookie', [`accessToken=${adminToken}`])
        .send({ role: 'editor' });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('role', 'editor');

      // Verify the role was actually updated
      const updatedUser = await User.findById(userId);
      expect(updatedUser.role).toBe('editor');
    });

    it('should not allow regular user to update roles', async () => {
      const res = await request(app)
        .put(`/admin/users/${userId}/role`)
        .set('Cookie', [`accessToken=${userToken}`])
        .send({ role: 'editor' });

      expect(res.status).toBe(403);
    });

    it('should validate role input', async () => {
      const res = await request(app)
        .put(`/admin/users/${userId}/role`)
        .set('Cookie', [`accessToken=${adminToken}`])
        .send({ role: 'invalid_role' });

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('message', 'Invalid role');
    });

    it('should handle non-existent user', async () => {
      const nonExistentId = '507f1f77bcf86cd799439011'; // Random valid ObjectId
      const res = await request(app)
        .put(`/admin/users/${nonExistentId}/role`)
        .set('Cookie', [`accessToken=${adminToken}`])
        .send({ role: 'editor' });

      expect(res.status).toBe(404);
      expect(res.body).toHaveProperty('message', 'User not found');
    });
  });
});
