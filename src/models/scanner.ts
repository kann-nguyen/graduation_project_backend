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

   // New property to store the endpoint URL of the running Docker container
   @prop()
   public endpoint?: string;

  // Add scanner type to identify which adapter to use
  @prop({ required: true })
  public type!: string; // 'sonarqube', 'trivy', 'grype', 'zap', etc.

  // Optional: Add expected result format info
  @prop()
  public resultFormat?: string; // 'json', 'xml', 'sarif'
}
