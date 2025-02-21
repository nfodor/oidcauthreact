import React, { useState, useEffect } from 'react';
import { login, register, logout } from '../services/auth';
import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

const AuthTest = () => {
  const [user, setUser] = useState(null);
  const [content, setContent] = useState([]);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleLogin = async () => {
    try {
      setLoading(true);
      setError(null);
      console.log('Attempting login...');
      const result = await login('admin@example.com', 'admin123');
      console.log('Login successful:', result);
      setUser(result.user);
      await fetchContent();
    } catch (err) {
      console.error('Login error:', err.response?.data || err);
      if (err.response?.status === 401) {
        setError('Invalid email or password. Please try again.');
      } else {
        setError(err.response?.data?.message || 'Login failed');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async () => {
    try {
      setLoading(true);
      setError(null);
      console.log('Attempting registration...');
      const result = await register('test@example.com', 'test123', 'Test User');
      console.log('Registration successful:', result);
      setUser(result.user);
      await fetchContent();
    } catch (err) {
      console.error('Register error:', err.response?.data || err);
      if (err.response?.data?.code === 'USER_EXISTS') {
        // If user exists, try to login instead
        try {
          console.log('User exists, attempting login...');
          const loginResult = await login('test@example.com', 'test123');
          console.log('Login successful:', loginResult);
          setUser(loginResult.user);
          await fetchContent();
        } catch (loginErr) {
          console.error('Login after register error:', loginErr.response?.data || loginErr);
          if (loginErr.response?.status === 401) {
            setError('Account exists but password is incorrect. Please try again.');
          } else {
            setError('Failed to login with existing account: ' + (loginErr.response?.data?.message || loginErr.message));
          }
        }
      } else {
        setError(err.response?.data?.message || 'Registration failed');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      setLoading(true);
      setError(null);
      await logout();
      setUser(null);
      setContent([]);
    } catch (err) {
      setError(err.response?.data?.message || 'Logout failed');
    } finally {
      setLoading(false);
    }
  };

  const fetchContent = async () => {
    try {
      const response = await axios.get(`${API_URL}/content`);
      setContent(response.data);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to fetch content');
    }
  };

  // Test protected endpoint access every 10 seconds
  useEffect(() => {
    if (user) {
      const interval = setInterval(fetchContent, 10000);
      return () => clearInterval(interval);
    }
  }, [user]);

  return (
    <div style={{ padding: '20px', maxWidth: '600px', margin: '0 auto' }}>
      <h1>Auth Test</h1>
      
      {error && (
        <div style={{ 
          padding: '10px', 
          backgroundColor: '#ffebee', 
          color: '#c62828',
          marginBottom: '20px',
          borderRadius: '4px'
        }}>
          Error: {error}
        </div>
      )}

      <div style={{ marginBottom: '20px' }}>
        {!user ? (
          <div>
            <button 
              onClick={handleLogin}
              disabled={loading}
              style={{ marginRight: '10px' }}
            >
              {loading ? 'Loading...' : 'Login (admin@example.com)'}
            </button>
            <button 
              onClick={handleRegister}
              disabled={loading}
            >
              {loading ? 'Loading...' : 'Register (test@example.com)'}
            </button>
          </div>
        ) : (
          <div>
            <p>Logged in as: {user.email} (Role: {user.role})</p>
            <button 
              onClick={handleLogout}
              disabled={loading}
            >
              {loading ? 'Loading...' : 'Logout'}
            </button>
          </div>
        )}
      </div>

      {user && (
        <div>
          <h2>Protected Content</h2>
          <p>Content will refresh every 10 seconds to test token refresh</p>
          <pre style={{ 
            backgroundColor: '#f5f5f5', 
            padding: '10px',
            borderRadius: '4px',
            overflow: 'auto'
          }}>
            {JSON.stringify(content, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};

export default AuthTest;
