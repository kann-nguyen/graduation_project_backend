import { ArraySubDocumentType, post, prop } from "@typegoose/typegoose";
import { Base } from "@typegoose/typegoose/lib/defaultClasses";
import permissions from "../utils/permission";
import { AccountModel, ProjectModel, ScannerModel, UserModel } from "./models";
import { Scanner } from "./scanner";
import { ThirdParty } from "./thirdParty";
class AccountScanner {
  @prop()
  public endpoint?: string;

  @prop({ type: () => Scanner, required: true })
  public details!: Scanner;
}
export interface Account extends Base {}
@post<Account>("save", async function () {
  const account = await AccountModel.findOne({ username: this.username });
  // Set permission based on role
  if (this.role === "admin") {
    await AccountModel.findByIdAndUpdate(account?._id, {
      permission: permissions,
    });
  } else if (this.role === "manager") {
    const perm = permissions.filter((p) => {
      if (!p.includes("user")) return true;
    });
    await AccountModel.findByIdAndUpdate(account?._id, {
      permission: perm,
    });
  } else {
    const perm = permissions.filter((p) => {
      if (
        !p.includes("user") &&
        p.includes("phase") &&
        !p.includes("project") &&
        !p.includes("artifact")
      )
        return true;
    });
    await AccountModel.findByIdAndUpdate(account?._id, {
      permission: perm,
    });
  }
  // Set scanner preference
  const scanner = await ScannerModel.findOne({ name: "Grype" });
  if (scanner) {
    await AccountModel.findByIdAndUpdate(account?._id, {
      scanner: {
        details: scanner,
      },
    });
  }
})
// Cascade delete on linking account
@post<Account>("findOneAndDelete", async function (this, doc) {
  if (!doc) return;
  const deleteUser = UserModel.findOneAndDelete({
    account: doc._id,
  });
  const deleteProject = ProjectModel.findOneAndDelete({
    createdBy: `Github_${doc.username}`,
  });
  // Optionally, delete tasks, tickets and history (TODO?)
  await Promise.all([deleteUser, deleteProject]);
})
export class Account {
  @prop({ required: true, type: String })
  public username!: string;

  @prop({ required: true, type: String })
  public password!: string;

  @prop({ lowercase: true, type: String })
  public email?: string;

  @prop({ type: () => ThirdParty, default: [], required: true })
  public thirdParty!: ArraySubDocumentType<ThirdParty>[];

  @prop({ type: () => AccountScanner })
  public scanner!: AccountScanner;

  @prop({
    enum: ["admin", "manager", "member"],
    default: "member",
    type: String,
  })
  public role?: string;

  @prop({ required: true, type: () => [String], default: [] })
  public permission!: string[];
}
