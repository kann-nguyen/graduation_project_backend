import { Ref, prop } from "@typegoose/typegoose";
import { Base, TimeStamps } from "@typegoose/typegoose/lib/defaultClasses";
import { Phase } from "./phase";
export interface Project extends Base {}
export class Project extends TimeStamps {
  @prop({ required: true, type: String })
  public name!: string;

  @prop({ type: String, required: true })
  public url!: string;

  @prop({
    required: true,
    enum: ["active", "inactive"],
    default: "active",
    type: String,
  })
  public status!: string;

  @prop({ type: String })
  public description?: string;

  @prop({ type: Date })
  public startDate?: Date;

  @prop({ type: Date })
  public endDate?: Date;

  @prop({ type: String })
  public createdBy?: string;

  @prop({ type: String })
  public updatedBy?: string;

  @prop({ ref: "Phase", default: [], required: true })
  public phaseList!: Ref<Phase>[];
}
