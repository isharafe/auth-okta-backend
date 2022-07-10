/**
 * Required External Modules and Interfaces
 */
import express, { Request, Response } from "express";
import { Student } from "../model/student";
import * as EmployeeService from "../service/employee.service";
/**
 * Router Definition
 */

export const studentRouter = express.Router();

/**
 * Controller Definitions
 */

// GET student
studentRouter.get("/:id", async (req: Request, res: Response) => {
    try {
        const stuId = req.params.id;
        const student = new Student(`stu ${stuId}`);
        res.status(200).send({data: student.toString()});
    } catch (e: any) {
        res.status(500).send(e.message);
    }
});
