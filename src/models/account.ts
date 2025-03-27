import { pre, prop, post } from "@typegoose/typegoose";
import { Base } from "@typegoose/typegoose/lib/defaultClasses";
import { ScannerModel, AccountModel } from "./models";
import { Scanner } from "./scanner";
import permissions from "../utils/permission";

class AccountScanner {
  @prop()
  public endpoint?: string;

  @prop({ type: () => Scanner, required: true })
  public details!: Scanner;
}

export interface Account extends Base {}

@pre<Account>("save", async function (next) {
  if (!this.scanner) {
    console.log("[INFO] Setting default scanner for new account...");
    const scanner = await ScannerModel.findOne({ name: "Grype" });
    if (scanner) {
      this.scanner = { details: scanner };
      console.log("[SUCCESS] Default scanner set to Grype.");
    } else {
      console.warn("[WARNING] No default scanner found! Skipping...");
    }
  }
  next();
})

@post<Account>("save", async function () {
  const account = await AccountModel.findOne({ username: this.username });

  // Set permission based on role
  if (this.role === "admin") {
    await AccountModel.findByIdAndUpdate(account?._id, {
      permission: permissions,
    });
  } else if (this.role === "manager") {
    const perm = permissions.filter((p) => !p.includes("user"));
    await AccountModel.findByIdAndUpdate(account?._id, {
      permission: perm,
    });
  } else {
    const perm = permissions.filter(
      (p) =>
        !p.includes("user") &&
        p.includes("phase") &&
        !p.includes("project") &&
        !p.includes("artifact")
    );
    await AccountModel.findByIdAndUpdate(account?._id, {
      permission: perm,
    });
  }
})

export class Account {
  @prop({ required: true, type: String })
  public username!: string;

  @prop({ required: true, type: String })
  public password!: string;

  @prop({ lowercase: true, type: String })
  public email?: string;

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
