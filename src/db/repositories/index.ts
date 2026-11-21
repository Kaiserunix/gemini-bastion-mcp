import type { GatewayDatabase } from '../sqlite.js';
import { AuditRepository, type AuditRepositoryOptions } from './auditRepo.js';
import { JobRepository } from './jobRepo.js';
import { OAuthRepository } from './oauthRepo.js';
import { PlanRepository } from './planRepo.js';
import { WorkspaceRepository } from './workspaceRepo.js';

export { AuditRepository, type AuditRepositoryOptions } from './auditRepo.js';
export { JobRepository } from './jobRepo.js';
export { OAuthRepository } from './oauthRepo.js';
export { PlanRepository, type ClaimPlanResult } from './planRepo.js';
export { WorkspaceRepository } from './workspaceRepo.js';

export interface Repositories {
  oauth: OAuthRepository;
  workspaces: WorkspaceRepository;
  jobs: JobRepository;
  plans: PlanRepository;
  audit: AuditRepository;
}

export function createRepositories(
  db: GatewayDatabase,
  auditOptions?: AuditRepositoryOptions,
): Repositories {
  return {
    oauth: new OAuthRepository(db),
    workspaces: new WorkspaceRepository(db),
    jobs: new JobRepository(db),
    plans: new PlanRepository(db),
    audit: new AuditRepository(db, auditOptions),
  };
}
