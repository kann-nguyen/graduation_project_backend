import { getModelForClass } from "@typegoose/typegoose";
import { Account } from "./account";
import { ActivityHistory } from "./activityHistory";
import { Artifact } from "./artifact";
import { CWE } from "./cwe";
import { Mitigation } from "./mitigation";
import { Phase } from "./phase";
import { Project } from "./project";
import { Task } from "./task";
import { ThirdParty } from "./thirdParty";
import { Threat } from "./threat";
import { Ticket } from "./ticket";
import { User } from "./user";
import { Vulnerability } from "./vulnerability";
import { PhaseTemplate } from "./phaseTemplate";
import { Scanner } from "./scanner";
import { ResolutionHistory } from "./resolutionHistory";
import { ChangeHistory } from "./changeHistory";

const AccountModel = getModelForClass(Account);
const ActivityHistoryModel = getModelForClass(ActivityHistory);
const ArtifactModel = getModelForClass(Artifact);
const CWEModel = getModelForClass(CWE);
const MitigationModel = getModelForClass(Mitigation);
const PhaseModel = getModelForClass(Phase);
const PhaseTemplateModel = getModelForClass(PhaseTemplate);
const ProjectModel = getModelForClass(Project);
const TaskModel = getModelForClass(Task);
const ThirdPartyModel = getModelForClass(ThirdParty);
const ThreatModel = getModelForClass(Threat);
const TicketModel = getModelForClass(Ticket);
const UserModel = getModelForClass(User);
const VulnerabilityModel = getModelForClass(Vulnerability);
const ScannerModel = getModelForClass(Scanner);
const ResolutionHistoryModel = getModelForClass(ResolutionHistory);
const ChangeHistoryModel = getModelForClass(ChangeHistory);
export {
  AccountModel,
  ActivityHistoryModel,
  ArtifactModel,
  CWEModel,
  MitigationModel,
  PhaseModel,
  PhaseTemplateModel,
  ProjectModel,
  TaskModel,
  ThirdPartyModel,
  ThreatModel,
  TicketModel,
  UserModel,
  VulnerabilityModel,
  ScannerModel,
  ResolutionHistoryModel,
  ChangeHistoryModel,
};
