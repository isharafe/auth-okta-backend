import { model, Schema } from "mongoose";
import { IPerson } from "./person.interface";

export interface IEmployee extends IPerson {
    empId: string;
    name?: string;
}

export const employeeSchema = new Schema<IEmployee>({
    empId: {type: String, required: true},
    name: String
});

export const Employee = model<IEmployee>("Employee", employeeSchema);