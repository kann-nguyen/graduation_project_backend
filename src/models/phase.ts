import { Ref, prop } from "@typegoose/typegoose";
import { Base } from "@typegoose/typegoose/lib/defaultClasses";
import { Artifact } from "./artifact";
import { Task } from "./task";
import { Scanner } from "./scanner";
export interface Phase extends Base {}
export class Phase {
  @prop({ required: true, type: String })
  public name!: string;

  @prop({ type: String })
  public description?: string;

  @prop({ required: true, type: Number })
  public order!: number;

  @prop({ ref: () => Task, default: [], required: true })
  public tasks!: Ref<Task>[];

  @prop({ ref: () => Artifact, default: [] })
  public artifacts?: Ref<Artifact>[];

  @prop({ ref: () => Scanner, default: [] })
  public scanners?: Ref<Scanner>[];
}
