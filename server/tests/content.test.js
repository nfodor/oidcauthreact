const request = require('supertest');
const app = require('../server');
const { User } = require('../models/user');
const jwt = require('jsonwebtoken');

describe('Content Endpoints', () => {
  let adminToken, editorToken, userToken;
  let contentId, adminId, editorId, userId;

  const testContent = {
    title: 'Test Content',
    body: 'This is test content'
  };

  beforeEach(async () => {
    // Create users with different roles
    const admin = await request(app)
      .post('/auth/register')
      .send({
        email: 'admin@example.com',
        password: 'password123',
        name: 'Admin User'
      });
    
    const editor = await request(app)
      .post('/auth/register')
      .send({
        email: 'editor@example.com',
        password: 'password123',
        name: 'Editor User'
      });
    
    const user = await request(app)
      .post('/auth/register')
      .send({
        email: 'user@example.com',
        password: 'password123',
        name: 'Regular User'
      });

    // Store user IDs
    adminId = admin.body.user._id;
    editorId = editor.body.user._id;
    userId = user.body.user._id;

    // Set roles
    await User.findByIdAndUpdate(adminId, { role: 'admin' });
    await User.findByIdAndUpdate(editorId, { role: 'editor' });

    // Get updated users with their roles
    const updatedAdmin = await User.findById(adminId);
    const updatedEditor = await User.findById(editorId);
    const regularUser = await User.findById(userId);

    // Generate tokens with updated roles
    const secret = process.env.JWT_SECRET || 'test_jwt_secret';
    
    adminToken = jwt.sign(
      { id: adminId, role: updatedAdmin.role },
      secret,
      { expiresIn: '15m' }
    );

    editorToken = jwt.sign(
      { id: editorId, role: updatedEditor.role },
      secret,
      { expiresIn: '15m' }
    );

    userToken = jwt.sign(
      { id: userId, role: regularUser.role },
      secret,
      { expiresIn: '15m' }
    );
  });

  describe('POST /content', () => {
    it('should allow admin to create content', async () => {
      const res = await request(app)
        .post('/content')
        .set('Cookie', [`accessToken=${adminToken}`])
        .send(testContent);

      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('title', testContent.title);
      expect(res.body).toHaveProperty('body', testContent.body);
      contentId = res.body._id;
    });

    it('should allow editor to create content', async () => {
      const res = await request(app)
        .post('/content')
        .set('Cookie', [`accessToken=${editorToken}`])
        .send(testContent);

      expect(res.status).toBe(201);
    });

    it('should not allow regular user to create content', async () => {
      const res = await request(app)
        .post('/content')
        .set('Cookie', [`accessToken=${userToken}`])
        .send(testContent);

      expect(res.status).toBe(403);
    });
  });

  describe('GET /content', () => {
    beforeEach(async () => {
      // Create test content
      const res = await request(app)
        .post('/content')
        .set('Cookie', [`accessToken=${adminToken}`])
        .send(testContent);
      contentId = res.body._id;
    });

    it('should allow any authenticated user to view content', async () => {
      const res = await request(app)
        .get('/content')
        .set('Cookie', [`accessToken=${userToken}`]);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body[0]).toHaveProperty('title', testContent.title);
    });

    it('should not allow unauthenticated access', async () => {
      const res = await request(app)
        .get('/content');

      expect(res.status).toBe(401);
    });
  });

  describe('PUT /content/:id', () => {
    beforeEach(async () => {
      // Create test content
      const res = await request(app)
        .post('/content')
        .set('Cookie', [`accessToken=${adminToken}`])
        .send(testContent);
      contentId = res.body._id;
    });

    const updates = {
      title: 'Updated Title',
      body: 'Updated content body'
    };

    it('should allow admin to update content', async () => {
      const res = await request(app)
        .put(`/content/${contentId}`)
        .set('Cookie', [`accessToken=${adminToken}`])
        .send(updates);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('title', updates.title);
      expect(res.body).toHaveProperty('body', updates.body);
    });

    it('should allow editor to update content', async () => {
      const res = await request(app)
        .put(`/content/${contentId}`)
        .set('Cookie', [`accessToken=${editorToken}`])
        .send(updates);

      expect(res.status).toBe(200);
    });

    it('should not allow regular user to update content', async () => {
      const res = await request(app)
        .put(`/content/${contentId}`)
        .set('Cookie', [`accessToken=${userToken}`])
        .send(updates);

      expect(res.status).toBe(403);
    });
  });

  describe('DELETE /content/:id', () => {
    beforeEach(async () => {
      // Create test content
      const res = await request(app)
        .post('/content')
        .set('Cookie', [`accessToken=${adminToken}`])
        .send(testContent);
      contentId = res.body._id;
    });

    it('should allow admin to delete content', async () => {
      const res = await request(app)
        .delete(`/content/${contentId}`)
        .set('Cookie', [`accessToken=${adminToken}`]);

      expect(res.status).toBe(204);
    });

    it('should not allow editor to delete content', async () => {
      const res = await request(app)
        .delete(`/content/${contentId}`)
        .set('Cookie', [`accessToken=${editorToken}`]);

      expect(res.status).toBe(403);
    });

    it('should not allow regular user to delete content', async () => {
      const res = await request(app)
        .delete(`/content/${contentId}`)
        .set('Cookie', [`accessToken=${userToken}`]);

      expect(res.status).toBe(403);
    });
  });
});
