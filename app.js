const express = require('express');
const morgan = require('morgan');
const swaggerUi = require('swagger-ui-express');
const swaggerSpec = require('./swagger/swaggerSpec');
const jobRouter = require('./routes/jobRoutes');
const userRouter = require('./routes/userRoutes');
const globalErrorHandler = require('./controllers/errorController');
const AppError = require('./utils/AppError');

const app = express();

/** User morgan middleware in development environment */
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

/** Swagger */
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

/** Use the body parser middleware */
app.use(express.json());

/** Mount the routers */
app.use('/api/v1/jobs', jobRouter);
app.use('/api/v1/users', userRouter);

app.use('*', (req, res, next) => {
  const message = `The resource ${req.method} ${req.originalUrl} is not found on the server ${req.get('host')}`;
  const appError = new AppError(404, message);
  next(appError);
});

app.use(globalErrorHandler);

module.exports = app;
