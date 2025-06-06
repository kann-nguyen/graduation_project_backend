import { ArraySubDocumentType, mongoose, post, prop, Ref, modelOptions } from "@typegoose/typegoose";
import { Base, TimeStamps } from "@typegoose/typegoose/lib/defaultClasses";
import { Threat } from "./threat";
import { Vulnerability } from "./vulnerability";
import { TicketModel } from "./models";
import { Types } from "mongoose";
// Define a separate class for scan history items
class ScanHistoryItem {
  @prop({ required: true })
  public timestamp!: Date;

  @prop({ type: () => [Vulnerability] })
  public vulnerabilities!: ArraySubDocumentType<Vulnerability>[];
}

export interface Artifact extends Base {}
@post<Artifact>("findOneAndDelete", async function (this, doc) {
  doc.threatList?.forEach(async (threat) => {
    await TicketModel.deleteMany({
      targetedThreat: threat,
    });
  });
})
@modelOptions({ 
  options: { 
    allowMixed: 0 // This will prevent "Mixed" type warnings
  }
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
  @prop({ default: false, select: false })
  public isScanning?: boolean; // trạng thái đang quét hay không
    @prop({ select: false, type: () => [Vulnerability] }) // không lưu trong DB
  public tempVuls?: ArraySubDocumentType<Vulnerability>[]; // danh sách vuln tạm thời từ scanner
  
  @prop({ 
    default: [],
    type: () => [ScanHistoryItem]
  })
  public scanHistory?: ArraySubDocumentType<ScanHistoryItem>[]; // history of all scans for tracking
}
