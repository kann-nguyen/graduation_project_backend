export interface Result {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  format: string;
  version: string;
  timestamp: Date;
  vulnerabilities: Vulnerability[];
}

export interface Vulnerability {
  cve: Cve;
}

export interface Cve {
  id: string;
  sourceIdentifier: SourceIdentifierEnum;
  published: Date;
  lastModified: Date;
  vulnStatus: VulnStatus;
  descriptions: Description[];
  metrics: Metrics;
  weaknesses: Weakness[];
  configurations: Configuration[];
  references: Reference[];
  evaluatorComment?: string;
  cisaExploitAdd?: Date;
  cisaActionDue?: Date;
  cisaRequiredAction?: string;
  cisaVulnerabilityName?: string;
}

export interface Configuration {
  nodes: Node[];
  operator?: ConfigurationOperator;
}

export interface Node {
  operator: NodeOperator;
  negate: boolean;
  cpeMatch: CpeMatch[];
}

export interface CpeMatch {
  vulnerable: boolean;
  criteria: string;
  matchCriteriaId: string;
  versionStartIncluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
}

export enum NodeOperator {
  Or = "OR",
}

export enum ConfigurationOperator {
  And = "AND",
}

export interface Description {
  lang: Lang;
  value: string;
}

export enum Lang {
  En = "en",
  Es = "es",
}

export interface Metrics {
  cvssMetricV2: CvssMetricV2[];
  cvssMetricV30?: CvssMetricV3[];
  cvssMetricV31?: CvssMetricV3[];
}

export interface CvssMetricV2 {
  source: CvssMetricV2Source;
  type: Type;
  cvssData: CvssMetricV2CvssData;
  baseSeverity: Severity;
  exploitabilityScore: number;
  impactScore: number;
  acInsufInfo: boolean;
  obtainAllPrivilege: boolean;
  obtainUserPrivilege: boolean;
  obtainOtherPrivilege: boolean;
  userInteractionRequired: boolean;
}

export enum Severity {
  High = "HIGH",
  Low = "LOW",
  Medium = "MEDIUM",
}

export interface CvssMetricV2CvssData {
  version: string;
  vectorString: string;
  accessVector: Vector;
  accessComplexity: Severity;
  authentication: Authentication;
  confidentialityImpact: SeverityImpact;
  integrityImpact: SeverityImpact;
  availabilityImpact: SeverityImpact;
  baseScore: number;
}

export enum Vector {
  Local = "LOCAL",
  Network = "NETWORK",
}

export enum Authentication {
  None = "NONE",
  Single = "SINGLE",
}

export enum SeverityImpact {
  Complete = "COMPLETE",
  None = "NONE",
  Partial = "PARTIAL",
}

export enum CvssMetricV2Source {
  MeissnerSUSEDe = "meissner@suse.de",
  NvdNISTGov = "nvd@nist.gov",
  SecurityApacheOrg = "security@apache.org",
}

export enum Type {
  Primary = "Primary",
  Secondary = "Secondary",
}

export interface CvssMetricV3 {
  source: CvssMetricV2Source;
  type: Type;
  cvssData: CvssMetricV30CvssData;
  exploitabilityScore: number;
  impactScore: number;
}

export interface CvssMetricV30CvssData {
  version: string;
  vectorString: string;
  attackVector: Vector;
  attackComplexity: Severity;
  privilegesRequired: AvailabilityImpact;
  userInteraction: UserInteraction;
  scope: Scope;
  confidentialityImpact: AvailabilityImpact;
  integrityImpact: AvailabilityImpact;
  availabilityImpact: AvailabilityImpact;
  baseScore: number;
  baseSeverity: BaseSeverity;
}

export enum AvailabilityImpact {
  High = "HIGH",
  Low = "LOW",
  None = "NONE",
}

export enum BaseSeverity {
  Critical = "CRITICAL",
  High = "HIGH",
  Medium = "MEDIUM",
}

export enum Scope {
  Changed = "CHANGED",
  Unchanged = "UNCHANGED",
}

export enum UserInteraction {
  None = "NONE",
  Required = "REQUIRED",
}

export interface Reference {
  url: string;
  source: SourceIdentifierEnum;
  tags?: Tag[];
}

export enum SourceIdentifierEnum {
  CveMitreOrg = "cve@mitre.org",
  MeissnerSUSEDe = "meissner@suse.de",
  SecalertRedhatCOM = "secalert@redhat.com",
  SecalertUsOracleCOM = "secalert_us@oracle.com",
  SecurityApacheOrg = "security@apache.org",
}

export enum Tag {
  BrokenLink = "Broken Link",
  Exploit = "Exploit",
  IssueTracking = "Issue Tracking",
  MailingList = "Mailing List",
  Mitigation = "Mitigation",
  Patch = "Patch",
  ReleaseNotes = "Release Notes",
  TechnicalDescription = "Technical Description",
  ThirdPartyAdvisory = "Third Party Advisory",
  USGovernmentResource = "US Government Resource",
  VDBEntry = "VDB Entry",
  VendorAdvisory = "Vendor Advisory",
}

export enum VulnStatus {
  Analyzed = "Analyzed",
  Modified = "Modified",
}

export interface Weakness {
  source: CvssMetricV2Source;
  type: Type;
  description: Description[];
}
