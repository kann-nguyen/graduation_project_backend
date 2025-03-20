import { prop } from "@typegoose/typegoose";
import { Base } from "@typegoose/typegoose/lib/defaultClasses";
export interface CWE extends Base {}
export class CWE {
  @prop({ required: true, type: String })
  public cweId!: string;

  @prop({ required: true, type: String })
  public name!: string;

  @prop({ required: true, type: String })
  public description!: string;

  @prop({ required: true, type: () => [String] })
  public modesOfIntroduction!: string[];

  @prop({ enum: ["Low", "Medium", "High", "Unknown"], type: String })
  public likelihood?: string;

  @prop({ required: true, type: () => [String] })
  public mitigation!: string[];

  @prop({ required: true, type: () => [String] })
  public consequences!: string[];

  @prop({ required: true, type: () => [String] })
  public detectionMethods!: string[];
}
