const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'Goverment Job Updates',
    version: '1.0.0',
    description: 'A simple government job postings information and updates'
  },
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT'
      }
    }
  },
  security: [
    {
      bearerAuth: []
    }
  ]
};

module.exports = swaggerDefinition;
