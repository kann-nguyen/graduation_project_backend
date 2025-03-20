import { Ref, prop } from "@typegoose/typegoose";
import { Base, TimeStamps } from "@typegoose/typegoose/lib/defaultClasses";
import { Project } from "./project";
export interface ActivityHistory extends Base {}
export class ActivityHistory extends TimeStamps {
  @prop({ required: true, type: String })
  public id!: string;

  @prop({ required: true, enum: ["commit", "pr"], type: String })
  public action!: string;

  @prop({ required: true, type: String })
  public content!: string;

  @prop({ type: String })
  public createdBy?: string;

  @prop({ type: String })
  public updatedBy?: string;

  @prop({ ref: () => Project })
  public projectId?: Ref<Project>;
}
