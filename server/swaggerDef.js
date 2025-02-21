const options = {
  swaggerDefinition: {
    openapi: '3.0.0',
    info: {
      title: 'RBAC API Documentation',
      version: '1.0.0',
      description: 'API documentation for Role-Based Access Control (RBAC) system',
      contact: {
        name: 'API Support',
        email: 'support@example.com'
      },
      license: {
        name: 'MIT',
        url: 'https://opensource.org/licenses/MIT'
      },
      termsOfService: 'http://example.com/terms/'
    },
    servers: [
      {
        url: 'http://localhost:5000',
        description: 'Local Development Server'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      },
      schemas: {
        User: {
          type: 'object',
          properties: {
            email: {
              type: 'string',
              format: 'email'
            },
            name: {
              type: 'string'
            },
            role: {
              type: 'string',
              enum: ['user', 'admin', 'editor', 'viewer']
            },
            emailVerified: {
              type: 'boolean'
            }
          }
        },
        Content: {
          type: 'object',
          properties: {
            title: {
              type: 'string'
            },
            body: {
              type: 'string'
            },
            createdBy: {
              type: 'string',
              format: 'uuid'
            }
          }
        },
        Error: {
          type: 'object',
          properties: {
            message: {
              type: 'string'
            }
          }
        }
      }
    },
    tags: [
      {
        name: 'Authentication',
        description: 'User authentication endpoints'
      },
      {
        name: 'Content',
        description: 'Content management endpoints'
      }
    ],
    paths: {
      '/auth/register': {
        post: {
          tags: ['Authentication'],
          summary: 'Register a new user',
          description: 'Create a new user account with email and password',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['email', 'password', 'name'],
                  properties: {
                    email: {
                      type: 'string',
                      format: 'email'
                    },
                    password: {
                      type: 'string',
                      format: 'password'
                    },
                    name: {
                      type: 'string'
                    }
                  }
                }
              }
            }
          },
          responses: {
            201: {
              description: 'User registered successfully',
              content: {
                'application/json': {
                  schema: {
                    $ref: '#/components/schemas/User'
                  }
                }
              }
            },
            400: {
              description: 'Invalid input'
            }
          }
        }
      },
      '/auth/login': {
        post: {
          tags: ['Authentication'],
          summary: 'Login user',
          description: 'Authenticate user and receive JWT token',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['email', 'password'],
                  properties: {
                    email: {
                      type: 'string',
                      format: 'email'
                    },
                    password: {
                      type: 'string',
                      format: 'password'
                    }
                  }
                }
              }
            }
          },
          responses: {
            200: {
              description: 'Login successful',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      token: {
                        type: 'string'
                      },
                      user: {
                        $ref: '#/components/schemas/User'
                      }
                    }
                  }
                }
              }
            },
            401: {
              description: 'Invalid credentials'
            }
          }
        }
      },
      '/content': {
        post: {
          tags: ['Content'],
          summary: 'Create new content',
          description: 'Create new content (requires admin or editor role)',
          security: [
            {
              bearerAuth: []
            }
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['title', 'body'],
                  properties: {
                    title: {
                      type: 'string'
                    },
                    body: {
                      type: 'string'
                    }
                  }
                }
              }
            }
          },
          responses: {
            201: {
              description: 'Content created successfully',
              content: {
                'application/json': {
                  schema: {
                    $ref: '#/components/schemas/Content'
                  }
                }
              }
            },
            401: {
              description: 'Unauthorized'
            },
            403: {
              description: 'Forbidden - Insufficient permissions'
            }
          }
        },
        get: {
          tags: ['Content'],
          summary: 'Get all content',
          description: 'Retrieve all content items',
          security: [
            {
              bearerAuth: []
            }
          ],
          responses: {
            200: {
              description: 'List of content items',
              content: {
                'application/json': {
                  schema: {
                    type: 'array',
                    items: {
                      $ref: '#/components/schemas/Content'
                    }
                  }
                }
              }
            },
            401: {
              description: 'Unauthorized'
            }
          }
        }
      },
      '/content/{id}': {
        put: {
          tags: ['Content'],
          summary: 'Update content',
          description: 'Update existing content (requires admin or editor role)',
          security: [
            {
              bearerAuth: []
            }
          ],
          parameters: [
            {
              in: 'path',
              name: 'id',
              required: true,
              schema: {
                type: 'string'
              },
              description: 'Content ID'
            }
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    title: {
                      type: 'string'
                    },
                    body: {
                      type: 'string'
                    }
                  }
                }
              }
            }
          },
          responses: {
            200: {
              description: 'Content updated successfully',
              content: {
                'application/json': {
                  schema: {
                    $ref: '#/components/schemas/Content'
                  }
                }
              }
            },
            401: {
              description: 'Unauthorized'
            },
            403: {
              description: 'Forbidden - Insufficient permissions'
            },
            404: {
              description: 'Content not found'
            }
          }
        },
        get: {
          tags: ['Content'],
          summary: 'Get content by ID',
          description: 'Retrieve a specific content item by ID',
          security: [
            {
              bearerAuth: []
            }
          ],
          parameters: [
            {
              in: 'path',
              name: 'id',
              required: true,
              schema: {
                type: 'string'
              },
              description: 'Content ID'
            }
          ],
          responses: {
            200: {
              description: 'Content item',
              content: {
                'application/json': {
                  schema: {
                    $ref: '#/components/schemas/Content'
                  }
                }
              }
            },
            401: {
              description: 'Unauthorized'
            },
            404: {
              description: 'Content not found'
            }
          }
        },
        delete: {
          tags: ['Content'],
          summary: 'Delete content',
          description: 'Delete content by ID (requires admin role)',
          security: [
            {
              bearerAuth: []
            }
          ],
          parameters: [
            {
              in: 'path',
              name: 'id',
              required: true,
              schema: {
                type: 'string'
              },
              description: 'Content ID'
            }
          ],
          responses: {
            204: {
              description: 'Content deleted successfully'
            },
            401: {
              description: 'Unauthorized'
            },
            403: {
              description: 'Forbidden - Insufficient permissions'
            },
            404: {
              description: 'Content not found'
            }
          }
        }
      }
    }
  },
  apis: ['./server.js']
};

module.exports = options;