import { pre, prop } from "@typegoose/typegoose";
import { Base } from "@typegoose/typegoose/lib/defaultClasses";
export interface Threat extends Base {}
class DetailScore {
  @prop({ type: Number, required: true })
  public damage!: number;

  @prop({ type: Number, required: true })
  public reproducibility!: number;

  @prop({ type: Number, required: true })
  public exploitability!: number;

  @prop({ type: Number, required: true })
  public affectedUsers!: number;

  @prop({ type: Number, required: true })
  public discoverability!: number;
}
class Score {
  @prop({ type: Number, required: true })
  public total!: number;

  @prop({ type: DetailScore, required: true })
  public details!: DetailScore;
}
@pre<Threat>("save", function (next) {
  this.score.total =
    (this.score.details.damage +
      this.score.details.reproducibility +
      this.score.details.exploitability +
      this.score.details.affectedUsers +
      this.score.details.discoverability) /
    5;
  next();
})
export class Threat {
  @prop({ required: true, type: String })
  public name!: string;

  @prop({ required: true, type: String })
  public description!: string;

  @prop({
    required: true,
    type: String,
    enum: [
      "Spoofing",
      "Tampering",
      "Repudiation",
      "Information Disclosure",
      "Denial of Service",
      "Elevation of Privilege",
    ],
  })
  public type!: string;

  @prop({ type: [String], required: true, default: [] })
  public mitigation!: string[];

  @prop({ type: Score, required: true })
  public score!: Score;

  @prop({
    type: String,
    required: true,
    enum: ["Non mitigated", "Partially mitigated", "Fully mitigated"],
    default: "Non mitigated",
  })
  public status!: string;
}
