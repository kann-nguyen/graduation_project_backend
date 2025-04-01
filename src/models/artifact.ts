import { ArraySubDocumentType, post, prop } from "@typegoose/typegoose";
import { Base, TimeStamps } from "@typegoose/typegoose/lib/defaultClasses";
import { Threat } from "./threat";
import { Vulnerability } from "./vulnerability";
import { TicketModel } from "./models";
export interface Artifact extends Base {}
@post<Artifact>("findOneAndDelete", async function (this, doc) {
  doc.vulnerabilityList?.forEach(async (vuln) => {
    await TicketModel.deleteMany({
      targetedVulnerability: vuln,
    });
  });
})
export class Artifact extends TimeStamps {
  @prop({ required: true, type: String })
  public name!: string;

  @prop({
    required: true,
    enum: [
      "docs",
      "source code",
      "image",
      "test report",
      "version release",
      "deployment config",
      "log",
      "monitoring dashboard",
    ],
    type: String,
  })
  public type!: string;

  @prop({ type: String })
  public url?: string;

  @prop({ type: String })
  public version?: string;

  @prop({ type: () => Threat, default: [] })
  public threatList?: ArraySubDocumentType<Threat>[];

  @prop({ default: [], type: () => Vulnerability })
  public vulnerabilityList?: ArraySubDocumentType<Vulnerability>[];

  @prop({ type: String })
  public cpe?: string;

  @prop({
    enum: ["S1", "S2", "S3", "S4", "S5", "S6", "S7"],
    type: String,
  })
  public state!: string;
}
