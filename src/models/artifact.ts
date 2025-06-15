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

// Define workflow step data classes for each step
class DetectionStepData {
  @prop({ required: true })
  public completedAt!: Date;
  
  @prop({ type: () => [Vulnerability] })
  public listVuls?: ArraySubDocumentType<Vulnerability>[]; // All vulnerabilities info
  
  @prop({ default: 0 })
  public numberVuls?: number; // Total number of vulnerabilities detected
}

class ClassificationStepData {
  @prop()
  public completedAt?: Date;
  
  @prop({ type: () => [mongoose.Schema.Types.ObjectId], ref: () => Threat })
  public listThreats?: Types.ObjectId[]; // All threats info
  
  @prop({ default: 0 })
  public numberThreats?: number; // Total number of threats classified
}

class AssignmentStepData {
  @prop()
  public completedAt?: Date;
  
  @prop({ type: () => [mongoose.Schema.Types.ObjectId] })
  public listTickets?: Types.ObjectId[]; // All tickets info
  
  @prop({ default: 0 })
  public numberTicketsAssigned?: number; // Number of tickets that have been assigned
  
  @prop({ default: 0 })
  public numberTicketsNotAssigned?: number; // Number of tickets that haven't been assigned
}

class RemediationStepData {
  @prop()
  public completedAt?: Date;
  
  @prop({ type: () => [mongoose.Schema.Types.ObjectId] })
  public listTickets?: Types.ObjectId[]; // All tickets info
  
  @prop({ default: 0 })
  public numberTicketsSubmitted?: number; // Number of tickets that have been submitted
  
  @prop({ default: 0 })
  public numberTicketsNotSubmitted?: number; // Number of tickets that haven't been submitted
}

class VerificationStepData {
  @prop()
  public completedAt?: Date;

  @prop({ type: String })
  public notes?: string;
  
  @prop({ default: 0 })
  public numberTicketsResolved?: number; // Number of tickets resolved by this scan
  
  @prop({ default: 0 })
  public numberTicketsReturnedToProcessing?: number; // Number of tickets returned to processing state
}

// Define a class for storing the workflow cycle data
class WorkflowCycle {
  @prop({ required: true })
  public cycleNumber!: number;

  @prop({ required: true, default: 1 })
  public currentStep!: number; // 1 to 5 representing the 5 steps

  @prop({ type: () => DetectionStepData })
  public detection?: DetectionStepData;

  @prop({ type: () => ClassificationStepData })
  public classification?: ClassificationStepData;

  @prop({ type: () => AssignmentStepData })
  public assignment?: AssignmentStepData;

  @prop({ type: () => RemediationStepData })
  public remediation?: RemediationStepData;

  @prop({ type: () => VerificationStepData })
  public verification?: VerificationStepData;

  @prop({ required: true })
  public startedAt!: Date;

  @prop()
  public completedAt?: Date;
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
  @prop({ default: false})
  public isScanning?: boolean; // trạng thái đang quét hay không
  @prop({ default: 0 })
  public numberThreatSubmitted?: number; // số lượng threat đã xử lý (submit)
  
  @prop({ default: 0})
  public scannersCompleted?: number; // số lượng scanner đã hoàn thành

  @prop({ default: 0})
  public totalScanners?: number; // tổng số scanner cần chạy
  
  @prop({ default: 50 })
  public rateReScan?: number; // tỷ lệ threat cần hoàn thành trước khi rescan
  // / trạng thái đang quét hay không
    @prop({ select: false, type: () => [Vulnerability] }) // không lưu trong DB
  public tempVuls?: ArraySubDocumentType<Vulnerability>[]; // danh sách vuln tạm thời từ scanner
  
  @prop({ 
    default: [],
    type: () => [ScanHistoryItem]
  })
  public scanHistory?: ArraySubDocumentType<ScanHistoryItem>[]; // history of all scans for tracking

  // Workflow tracking
  @prop({ default: 0 })
  public workflowCyclesCount?: number; // Total number of cycles completed

  @prop({ default: 1 })
  public currentWorkflowStep?: number; // Current step in the workflow (1-5)

  @prop({ 
    default: [],
    type: () => [WorkflowCycle]
  })
  public workflowCycles?: ArraySubDocumentType<WorkflowCycle>[]; // All workflow cycles

  @prop({ type: () => WorkflowCycle })
  public currentWorkflowCycle?: WorkflowCycle; // Current active workflow cycle

  @prop({ default: false })
  public workflowCompleted?: boolean; // Whether the entire workflow (all cycles) is complete
}
