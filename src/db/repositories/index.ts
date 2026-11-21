import type { GatewayDatabase } from '../sqlite.js';
import { AuditRepository } from './auditRepo.js';
import { JobRepository } from './jobRepo.js';
import { MemoryRepository } from './memoryRepo.js';
import { OAuthRepository } from './oauthRepo.js';
import { PlanRepository } from './planRepo.js';
import { WorkspaceRepository } from './workspaceRepo.js';

export { AuditRepository } from './auditRepo.js';
export { JobRepository } from './jobRepo.js';
export {
  MAX_MEMORIES_PER_WORKSPACE,
  MAX_MEMORY_CONTENT_BYTES,
  MEMORY_CATEGORIES,
  MemoryRepository,
  type ListMemoriesFilter,
  type UpsertMemoryInput,
} from './memoryRepo.js';
export { OAuthRepository } from './oauthRepo.js';
export { PlanRepository, type ClaimPlanResult } from './planRepo.js';
export { WorkspaceRepository } from './workspaceRepo.js';

export interface Repositories {
  oauth: OAuthRepository;
  workspaces: WorkspaceRepository;
  memories: MemoryRepository;
  jobs: JobRepository;
  plans: PlanRepository;
  audit: AuditRepository;
}

export function createRepositories(db: GatewayDatabase): Repositories {
  return {
    oauth: new OAuthRepository(db),
    workspaces: new WorkspaceRepository(db),
    memories: new MemoryRepository(db),
    jobs: new JobRepository(db),
    plans: new PlanRepository(db),
    audit: new AuditRepository(db),
  };
}
