const request = require('supertest');
const app = require('../server');
const { User } = require('../models/user');
const jwt = require('jsonwebtoken');

describe('Authentication Endpoints', () => {
  const testUser = {
    email: 'test@example.com',
    password: 'password123',
    name: 'Test User'
  };

  describe('POST /auth/register', () => {
    it('should register a new user', async () => {
      const res = await request(app)
        .post('/auth/register')
        .send(testUser);

      expect(res.status).toBe(201);
      expect(res.body.user).toHaveProperty('email', testUser.email);
      expect(res.body.user).toHaveProperty('name', testUser.name);
      expect(res.body.user).not.toHaveProperty('password');
      expect(res.body).toHaveProperty('expiresIn');
      expect(res.headers['set-cookie']).toBeDefined();
    });

    it('should not register a user with existing email', async () => {
      // First registration
      await request(app)
        .post('/auth/register')
        .send(testUser);

      // Second registration with same email
      const res = await request(app)
        .post('/auth/register')
        .send(testUser);

      expect(res.status).toBe(409);
      expect(res.body).toHaveProperty('code', 'USER_EXISTS');
    });
  });

  describe('POST /auth/login', () => {
    beforeEach(async () => {
      // Register a user before each test
      await request(app)
        .post('/auth/register')
        .send(testUser);
    });

    it('should login with valid credentials', async () => {
      const res = await request(app)
        .post('/auth/login')
        .send({
          email: testUser.email,
          password: testUser.password
        });

      expect(res.status).toBe(200);
      expect(res.body.user).toHaveProperty('email', testUser.email);
      expect(res.body).toHaveProperty('expiresIn');
      expect(res.headers['set-cookie']).toBeDefined();
    });

    it('should not login with invalid password', async () => {
      const res = await request(app)
        .post('/auth/login')
        .send({
          email: testUser.email,
          password: 'wrongpassword'
        });

      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty('message', 'Invalid email or password');
    });
  });

  describe('POST /auth/refresh-token', () => {
    let refreshToken;

    beforeEach(async () => {
      // Register and login to get tokens
      const loginRes = await request(app)
        .post('/auth/register')
        .send(testUser);

      // Extract refresh token from cookie
      const cookies = loginRes.headers['set-cookie'];
      refreshToken = cookies.find(cookie => cookie.startsWith('refreshToken='))
        .split(';')[0]
        .split('=')[1];
    });

    it('should refresh tokens with valid refresh token', async () => {
      const res = await request(app)
        .post('/auth/refresh-token')
        .set('Cookie', [`refreshToken=${refreshToken}`]);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('expiresIn');
      expect(res.headers['set-cookie']).toBeDefined();
    });

    it('should not refresh tokens with invalid refresh token', async () => {
      const res = await request(app)
        .post('/auth/refresh-token')
        .set('Cookie', ['refreshToken=invalid_token']);

      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty('message', 'Invalid refresh token');
    });
  });

  describe('POST /auth/logout', () => {
    let accessToken;

    beforeEach(async () => {
      // Register and login to get tokens
      const loginRes = await request(app)
        .post('/auth/register')
        .send(testUser);

      // Extract access token from cookie
      const cookies = loginRes.headers['set-cookie'];
      accessToken = cookies.find(cookie => cookie.startsWith('accessToken='))
        .split(';')[0]
        .split('=')[1];
    });

    it('should logout successfully', async () => {
      const res = await request(app)
        .post('/auth/logout')
        .set('Cookie', [`accessToken=${accessToken}`]);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('message', 'Logged out successfully');
      
      // Check that cookies are cleared
      const cookies = res.headers['set-cookie'];
      expect(cookies.some(cookie => cookie.includes('accessToken=;'))).toBe(true);
      expect(cookies.some(cookie => cookie.includes('refreshToken=;'))).toBe(true);
    });

    it('should require authentication', async () => {
      const res = await request(app)
        .post('/auth/logout');

      expect(res.status).toBe(401);
    });
  });
});
