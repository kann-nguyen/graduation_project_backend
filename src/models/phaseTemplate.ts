import { ArraySubDocumentType, prop } from "@typegoose/typegoose";
import { Base } from "@typegoose/typegoose/lib/defaultClasses";
export interface PhaseTemplate extends Base {}
class Phase {
  @prop({ required: true, type: String })
  public name!: string;

  @prop({ type: String })
  public description?: string;

  @prop({ required: true, type: Number })
  public order!: number;
}

export class PhaseTemplate {
  @prop({ required: true, type: String })
  public name!: string;

  @prop({ type: String })
  public description?: string;

  @prop({ _id: false, type: () => Phase })
  public phases?: ArraySubDocumentType<Phase>[];

  @prop({ default: true, type: Boolean })
  public isPrivate?: boolean;

  @prop({ required: true, type: String })
  public createdBy!: string;
}
