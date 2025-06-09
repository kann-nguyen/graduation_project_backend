import { 
  VulnerabilityAdapter, 
  SonarQubeAdapter, 
  TrivyAdapter, 
  GrypeAdapter, 
  ZapAdapter,
  BanditAdapter,
  SemgrepAdapter
} from './vulnerabilityAdapters';

export class AdapterFactory {
  private static adapters: Map<string, VulnerabilityAdapter> = new Map([
    ['sonarqube', new SonarQubeAdapter()],
    ['trivy', new TrivyAdapter()],
    ['grype', new GrypeAdapter()],
    ['zap', new ZapAdapter()],
    ['bandit', new BanditAdapter()],
    ['semgrep', new SemgrepAdapter()]
  ]);

  static getAdapter(scannerType: string): VulnerabilityAdapter | null {
    return this.adapters.get(scannerType.toLowerCase()) || null;
  }

  static registerAdapter(scannerType: string, adapter: VulnerabilityAdapter): void {
    this.adapters.set(scannerType.toLowerCase(), adapter);
  }

  static getSupportedTypes(): string[] {
    return Array.from(this.adapters.keys());
  }

  static getAllAdapters(): Map<string, VulnerabilityAdapter> {
    return new Map(this.adapters);
  }
}
