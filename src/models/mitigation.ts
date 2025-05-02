import { prop } from "@typegoose/typegoose";
import { Base, TimeStamps } from "@typegoose/typegoose/lib/defaultClasses";
import mongoose from "mongoose";
import { User } from "./user";

/**
 * Interface extending Base to use Typegoose default properties
 */
export interface Mitigation extends Base {}

/**
 * Mitigation model to store structured mitigation data for threats
 */
export class Mitigation extends TimeStamps {
  @prop({ required: true, type: String })
  public title!: string; // Title of the mitigation strategy

  @prop({ required: true, type: String })
  public description!: string; // Brief description of the mitigation

  @prop({ required: true, type: String })
  public implementation!: string; // Detailed implementation steps

  @prop({ ref: () => User })
  public createdBy?: mongoose.Types.ObjectId; // User who created the mitigation
}