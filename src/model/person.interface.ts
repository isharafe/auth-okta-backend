import { IModelBase } from "./model-base.interface";

export interface IPerson extends IModelBase {
    name?: string;
    nic?: string;

}