/**
* Required External Modules
*/

import * as dotenv from "dotenv";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import { employeeRouter } from "./controller/employee.controller";
import { errorHandler } from "./middleware/error.middleware";
import { notFoundHandler } from "./middleware/not-found.middleware";
import { studentRouter } from "./controller/student.controller";
import { dbConnect } from "./service/db.service";
import { authRouter } from "./service/auth.service";

dotenv.config();

/**
 * App Variables
 */

if (!process.env.PORT) {
    process.exit(1);
}

const PORT: number = parseInt(process.env.PORT as string, 10);

const app = express();

/**
 *  App Configuration
 */

app.use(helmet());
app.use(cors());
app.use(express.json());

 // auth router attaches /login, /logout, and /callback routes to the baseURL
// app.use(openIdAuthConnect);
// app.use(authRouter);

app.use("/api/auth", authRouter);
app.use("/api/employees", employeeRouter);
app.use("/api/students", studentRouter);
 
 /** error handler function should register
  * after all routes are registered.
  * this fn should have four arguments.
  * o/w express don't recognize this as error handler
  * */
app.use(errorHandler);

 /**
  * route not found won't be handled from error handler.
  * register this as the last middleware.
  * so that all the things didn't catch above,
  * will be catched from here.
  */
app.use(notFoundHandler);

/**
 * DB Connect
 */
dbConnect().catch(err => console.log("error while db connect: ", err));

/**
 * Server Activation
 */
app.listen(PORT, () => {
    console.log(`Listening on port ${PORT}`);
});