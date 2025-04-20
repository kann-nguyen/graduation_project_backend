import { ArraySubDocumentType, post, prop, Ref } from "@typegoose/typegoose";
import { Base, TimeStamps } from "@typegoose/typegoose/lib/defaultClasses";
import { User } from "./user";
import { ChangeHistoryModel, UserModel } from "./models";
import { Threat } from "./threat";

export interface Ticket extends Base {}

@post<Ticket>("deleteMany", async function (res, next) {
  try {
    // Remove tickets from UserModel's ticketAssigned field
    await UserModel.updateMany({
      $pull: {
        ticketAssigned: {
          $in: res._id,
        },
      },
    });
    await ChangeHistoryModel.deleteMany({ objectId: res._id });
  } catch (error) {
    console.error(`❌ Error in deleteMany hook for Ticket: ${error}`);
  }
})
export class Ticket extends TimeStamps {
  @prop({ required: true, type: String })
  public title!: string;

  @prop({ ref: () => User, required: false }) // Make assignee optional
  public assignee?: Ref<User>;

  @prop({ ref: () => User })
  public assigner?: Ref<User>;

  @prop({
    required: true,
    enum: ["Not accepted", "Processing", "Submitted", "Resolved"],
    default: "Not accepted",
    type: String,
  })
  public status!: string;

  @prop({ type: String })
  public description?: string;

  @prop({
    required: true,
    enum: ["low", "medium", "high"],
    default: "low",
    type: String,
  })
  public priority!: string;

  @prop({ ref: () => Threat, required: true })
  public targetedThreat!: Ref<Threat>;

  @prop({ required: true, type: String, validate: (v: string) => v.trim().length > 0 })
  public projectName!: string;

  @prop({ required: true, type: String, validate: (v: string) => v.trim().length > 0 })
  public artifactId!: string;
}