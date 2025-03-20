import { prop } from "@typegoose/typegoose";
import { Base } from "@typegoose/typegoose/lib/defaultClasses";
export class Configuration {
  @prop({ required: true })
  public installCommand!: string;

  @prop({ required: true })
  public code!: string;
}
export interface Scanner extends Base {}
export class Scanner {
  @prop({ required: true })
  public name!: string;

  @prop({ required: true })
  public createdBy!: string;

  @prop()
  public updatedBy?: string;

  @prop()
  public config?: Configuration;
}
