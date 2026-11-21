import {
  applyPatch,
  createOrOverwriteFiles,
  deleteFiles,
  type ApplyPatchOptions,
  type CodePatchResult,
  type CreateOrOverwriteOptions,
  type DeleteFilesOptions,
} from '../../core/codePatcher.js';
import {
  initCfOpsWorkspace,
  rollbackToCheckpoint,
  syncGitHubRepo,
  type CfOpsContext,
  type InitCfOpsWorkspaceOptions,
  type RollbackOptions,
  type RollbackResult,
  type SyncGitHubRepoOptions,
  type SyncGitHubRepoResult,
} from '../../core/gitSnapshot.js';
import {
  runValidationPipeline,
  type ValidationPipelineOptions,
  type ValidationPipelineResult,
} from '../../core/validationPipeline.js';
import {
  workspaceExec,
  type WorkspaceExecOptions,
  type WorkspaceExecResult,
} from '../../core/workspaceExec.js';
import type { WorkspaceToolAdapter } from './types.js';

/**
 * Default workspace adapter delegating to the sandboxed core git, patcher,
 * validation pipeline, and workspace-exec modules.
 */
export class DefaultWorkspaceToolAdapter implements WorkspaceToolAdapter {
  syncGitHubRepo(options: SyncGitHubRepoOptions): Promise<SyncGitHubRepoResult> {
    return syncGitHubRepo(options);
  }

  initCfOpsWorkspace(options: InitCfOpsWorkspaceOptions): CfOpsContext {
    return initCfOpsWorkspace(options);
  }

  rollbackToCheckpoint(
    slug: string,
    checkpointId: string,
    options: RollbackOptions,
  ): Promise<RollbackResult> {
    return rollbackToCheckpoint(slug, checkpointId, options);
  }

  applyPatch(options: ApplyPatchOptions): Promise<CodePatchResult> {
    return applyPatch(options);
  }

  createOrOverwriteFiles(options: CreateOrOverwriteOptions): Promise<CodePatchResult> {
    return createOrOverwriteFiles(options);
  }

  deleteFiles(options: DeleteFilesOptions): Promise<CodePatchResult> {
    return deleteFiles(options);
  }

  workspaceExec(options: WorkspaceExecOptions): Promise<WorkspaceExecResult> {
    return workspaceExec(options);
  }

  runValidationPipeline(options: ValidationPipelineOptions): Promise<ValidationPipelineResult> {
    return runValidationPipeline(options);
  }
}

export const defaultWorkspaceToolAdapter = new DefaultWorkspaceToolAdapter();
