import { Employee, IEmployee } from "../model/employee";
import cacheService from "./cache.service";

export const findAll = async () : Promise<IEmployee[]> => {
    return await Employee.find();
};

export const find = async (id: number) : Promise<IEmployee> => {
    const cacheKey = `employee-${id}`;
    const cachedObj = cacheService.get(cacheKey) as IEmployee;
    if(cachedObj) {
        console.log("loaded from cache: ", cacheKey);
        return cachedObj;
    }
    const emp = await Employee.findOne({_id: id});
    console.log("cached missed: ", cacheKey);
    cacheService.set(cacheKey, emp);
    return (emp as IEmployee);
}

export const create = async (employee: IEmployee) : Promise<IEmployee> => {
    const emp = new Employee(employee);
    const saved = await emp.save();
    return saved;
}

export const update = async (id: any, employee: IEmployee) : Promise<IEmployee> => {
    const saved = await Employee.updateOne({_id: id}, employee);
    console.log("after save:", employee);
    return employee;
}

export const remove = async (id: any) : Promise<boolean> => {
    const result = await Employee.deleteOne({_id: id});
    return result.deletedCount > 0;
}