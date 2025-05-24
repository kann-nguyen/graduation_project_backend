import { ArraySubDocumentType, mongoose, post, prop, Ref } from "@typegoose/typegoose";
import { Base, TimeStamps } from "@typegoose/typegoose/lib/defaultClasses";
import { Threat } from "./threat";
import { Vulnerability } from "./vulnerability";
import { TicketModel } from "./models";
import { Types } from "mongoose";
export interface Artifact extends Base {}
@post<Artifact>("findOneAndDelete", async function (this, doc) {
  doc.threatList?.forEach(async (threat) => {
    await TicketModel.deleteMany({
      targetedThreat: threat,
    });
  });
})
export class Artifact extends TimeStamps {
  @prop({ required: true, type: String })
  public name!: string;

  @prop({
    required: true,
    enum: [
      "image", "log", "source code", "executable", "library"
    ],
    type: String,
  })
  public type!: string;

  @prop({ type: String })
  public url?: string;

  @prop({ type: String })
  public version?: string;

  @prop({ type: () => [mongoose.Schema.Types.ObjectId], ref: () => Threat })
  public threatList?: Types.ObjectId[];

  @prop({ default: [], type: () => Vulnerability })
  public vulnerabilityList?: ArraySubDocumentType<Vulnerability>[];

  @prop({ type: String })
  public cpe?: string;
  @prop({
    enum: ["valid", "invalid"],
    type: String,
    default: "valid",
    required: true
  })
  public state!: string;

  @prop({ required: true })
  public projectId!: mongoose.Types.ObjectId;

  @prop({ default: 0 })
  public numberThreatSubmitted?: number; // số lượng threat đã xử lý (submit)

  @prop({ default: 50 })
  public rateReScan?: number; // số lượng threat đã xử lý (submit)

  @prop({ default: 0, select: false })
  public scannersCompleted?: number; // số lượng scanner đã hoàn thành

  @prop({ default: 0,select: false  })
  public totalScanners?: number; // tổng số scanner cần chạy

  @prop({ default: false,select: false  })
  public isScanning?: boolean; // trạng thái đang quét hay không
  @prop({ select: false }) // không lưu trong DB
  public tempVuls?: ArraySubDocumentType<Vulnerability>[]; // danh sách vuln tạm thời từ scanner

  @prop({ default: [], type: () => [{
    timestamp: Date,
    vulnerabilities: () => [Vulnerability]
  }] })
  public scanHistory?: {
    timestamp: Date;
    vulnerabilities: ArraySubDocumentType<Vulnerability>[];
  }[]; // history of all scans for tracking
}
