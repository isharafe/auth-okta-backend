/**
 * Required External Modules and Interfaces
 */
import express, { Request, Response } from "express";
import { IEmployee } from "../model/employee";
import { authenticationRequired } from "../service/auth.service";
import * as EmployeeService from "../service/employee.service";
/**
 * Router Definition
 */

export const employeeRouter = express.Router();

/**
 * Controller Definitions
 */

// GET employees
employeeRouter.get("/", async (req: Request, res: Response) => {
    try {
        const employees = await EmployeeService.findAll();
        res.status(200).send(employees);
    } catch (e: any) {
        res.status(500).send(e.message);
    }
});

// GET employees/:id
employeeRouter.get("/:id", authenticationRequired, async (req: Request, res: Response) => {
    const id: any = req.params.id;

    try {
        const employee = await EmployeeService.find(id);
        if(employee) {
            return res.status(200).json(employee);
        }

        return res.status(404).send(`Employee for id ${id} not found !`);
    } catch (e: any) {
        res.status(500).send(e.message);
    }
});

// POST employees
employeeRouter.post("/", async (req: Request, res: Response) => {
    try {
        const employee: IEmployee = req.body;
        const saved = await EmployeeService.create(employee);
        res.status(201).send(saved);
    } catch (e: any) {
        res.status(500).send(e.message);
    }
});

// PUT employees/:id
employeeRouter.put("/:id", async (req: Request, res: Response) => {
    const id: any = req.params.id;

    try {
        const employee: IEmployee = req.body;
        const saved = await EmployeeService.update(id, employee);
        res.status(200).send(saved);
    } catch (e: any) {
        res.status(500).send(e.message);
    }
});

// DELETE employees/:id
employeeRouter.delete("/:id", async (req: Request, res: Response) => {
    const id: number = parseInt(req.params.id, 10);
    
    try {
        const result = await EmployeeService.remove(id);
        res.status(204).send(result);
    } catch (e: any) {
        res.status(500).send(e.message);
    }
});