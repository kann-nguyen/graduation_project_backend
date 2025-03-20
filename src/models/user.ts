import { Ref, prop } from "@typegoose/typegoose";
import { Base } from "@typegoose/typegoose/lib/defaultClasses";
import { Account } from "./account";
import { ActivityHistory } from "./activityHistory";
import { Project } from "./project";
import { Task } from "./task";
import { Ticket } from "./ticket";
export interface User extends Base {}
export class User {
  @prop({ required: true, type: String })
  public name!: string;

  @prop({ ref: () => Account, required: true })
  public account!: Ref<Account>;

  @prop({ ref: () => Task, default: [] })
  public taskAssigned!: Ref<Task>[];

  @prop({ ref: () => Ticket, default: [] })
  public ticketAssigned!: Ref<Ticket>[];

  @prop({ ref: () => ActivityHistory, default: [] })
  public activityHistory!: Ref<ActivityHistory>[];

  @prop({ ref: () => Project, default: [] })
  public projectIn!: Ref<Project>[];
}
