import { Person } from "./person.interface";

export class Student {
    constructor(
        private studentId: string
    ){

    }

    toString() : string {
        return this.studentId;
    }
}