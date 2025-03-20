import { Ref, prop } from "@typegoose/typegoose";
import { Base } from "@typegoose/typegoose/lib/defaultClasses";
import mongoose from "mongoose";
import { Account } from "./account";
export interface ChangeHistory extends Base {}
export class ChangeHistory {
  @prop({ required: true })
  public objectId!: mongoose.Types.ObjectId;
  @prop({ enum: ["create", "update", "delete"], required: true })
  public action!: string;
  @prop({ required: true, ref: () => Account })
  public account!: Ref<Account>;
  @prop({ required: true })
  public timestamp!: Date;
  @prop({ required: true })
  public description!: string;
}
