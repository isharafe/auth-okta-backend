import { connect } from "mongoose";
import * as dotenv from "dotenv";

dotenv.config();

export async function dbConnect() {
  // Connect to MongoDB
  const dbUrl = process.env.DB_CON_URL as string;
  console.log("trying to connect to database: ", dbUrl)
  await connect(dbUrl);
  console.log("database connected.");
}