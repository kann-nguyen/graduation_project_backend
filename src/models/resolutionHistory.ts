import { ArraySubDocumentType, prop } from "@typegoose/typegoose";
import { Base } from "@typegoose/typegoose/lib/defaultClasses";
class Resolution {
  @prop({ required: true })
  public createdBy!: string;
  @prop({ required: true })
  public description!: string;
  @prop()
  public isApproved?: boolean;
}
export interface ResolutionHistory extends Base {}
export class ResolutionHistory {
  @prop({ required: true })
  public cveId!: string;
  @prop({ required: true, type: () => Resolution })
  public resolution!: ArraySubDocumentType<Resolution>[];
}
