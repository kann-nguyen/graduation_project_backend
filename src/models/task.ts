import { post, prop } from "@typegoose/typegoose";
import { Base, TimeStamps } from "@typegoose/typegoose/lib/defaultClasses";
import { PhaseModel, UserModel } from "./models";

export interface Task extends Base {}
@post<Task>("findOneAndDelete", async function (this, doc) {
  if (!doc) return;
  // Remove task from phase
  const deleteFromPhase = PhaseModel.findOneAndUpdate(
    { tasks: doc._id },
    { $pull: { tasks: doc._id } }
  );
  // Remove task from user
  const deleteFromUser = UserModel.findOneAndUpdate(
    { tasks: doc._id },
    { $pull: { tasks: doc._id } }
  );
  await Promise.all([deleteFromPhase, deleteFromUser]);
})
export class Task extends TimeStamps {
  @prop({ required: true, type: String })
  public name!: string;

  @prop({
    required: true,
    enum: ["active", "completed"],
    default: "active",
    type: String,
  })
  public status!: string;

  @prop({ require: true, type: String })
  public description!: string;

  @prop({ type: String })
  public createdBy?: string;

  @prop({ type: String })
  public updatedBy?: string;

  @prop({ required: true, type: String })
  public projectName!: string;

  @prop({ type: Date, required: true })
  public dueDate!: Date;
}
