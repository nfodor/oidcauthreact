import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';
let refreshTokenTimeout;

export const setAuthTokens = (expiresIn) => {
  // Set up automatic token refresh
  const refreshTime = (expiresIn * 0.9) * 1000; // 90% of expiry time in milliseconds
  if (refreshTokenTimeout) {
    clearTimeout(refreshTokenTimeout);
  }
  refreshTokenTimeout = setTimeout(refreshAccessToken, refreshTime);
};

export const clearAuthTokens = () => {
  if (refreshTokenTimeout) {
    clearTimeout(refreshTokenTimeout);
  }
};

export const refreshAccessToken = async () => {
  try {
    const response = await axios.post(`${API_URL}/auth/refresh-token`, {}, {
      withCredentials: true // Required for cookies
    });

    const { expiresIn } = response.data;
    setAuthTokens(expiresIn);
    
    return true;
  } catch (error) {
    console.error('Error refreshing token:', error);
    clearAuthTokens();
    window.location.href = '/login';
    throw error;
  }
};

// Axios interceptor to handle token expiration
axios.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    
    if (error.response?.status === 401 && 
        error.response?.data?.code === 'TOKEN_EXPIRED' && 
        !originalRequest._retry) {
      originalRequest._retry = true;
      
      try {
        await refreshAccessToken();
        return axios(originalRequest);
      } catch (refreshError) {
        return Promise.reject(refreshError);
      }
    }
    
    return Promise.reject(error);
  }
);

// Configure axios defaults
axios.defaults.withCredentials = true; // Required for cookies

export const login = async (email, password) => {
  try {
    const response = await axios.post(`${API_URL}/auth/login`, {
      email,
      password
    });

    const { expiresIn, user } = response.data;
    setAuthTokens(expiresIn);
    
    return { user };
  } catch (error) {
    console.error('Login error:', error);
    throw error;
  }
};

export const register = async (email, password, name) => {
  try {
    const response = await axios.post(`${API_URL}/auth/register`, {
      email,
      password,
      name
    });

    const { expiresIn, user } = response.data;
    setAuthTokens(expiresIn);
    
    return { user };
  } catch (error) {
    console.error('Registration error:', error);
    throw error;
  }
};

export const logout = async () => {
  try {
    await axios.post(`${API_URL}/auth/logout`);
    clearAuthTokens();
    window.location.href = '/login';
  } catch (error) {
    console.error('Logout error:', error);
    // Still clear tokens and redirect even if the server request fails
    clearAuthTokens();
    window.location.href = '/login';
  }
};
