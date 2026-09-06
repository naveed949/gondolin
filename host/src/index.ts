/**
 * @earendil-works/gondolin
 *
 * Alpine Linux sandbox for running untrusted code with controlled
 * filesystem and network access.
 */

// Main VM interface
export {
  VM,
  type VMOptions,
  type VMState,
  type VmRuntimeIdentity,
  type EnableSshOptions,
  type SshAccess,
  type VmFs,
  type VmRootfsOptions,
  type VmFsAccessOptions,
  type VmFsMkdirOptions,
  type VmFsListDirOptions,
  type VmFsStatOptions,
  type VmFsRenameOptions,
  type VmFsStat,
  type VmFsReadFileOptions,
  type VmFsReadFileBufferOptions,
  type VmFsReadFileTextOptions,
  type VmFsReadFileStreamOptions,
  type VmFsWriteFileInput,
  type VmFsWriteFileOptions,
  type VmFsDeleteOptions,
} from "./vm/core.ts";
export { VmCheckpoint, type VmCheckpointData } from "./checkpoint.ts";
export {
  type ExecOptions,
  type ExecResult,
  type ExecProcess,
  type ExecResourceLimits,
  type ExecResourceUsage,
} from "./exec.ts";

// Capability-aware, one-shot execution seam
export {
  CAPABILITY_CEILING_SCHEMA_VERSION,
  CAPABILITY_INVOCATION_SCHEMA_VERSION,
  CAPABILITY_EVIDENCE_SCHEMA_VERSION,
  CAPABILITY_EVIDENCE_GUARANTEES,
  EXACT_READER_GUARANTEES,
  EXACT_WRITER_GUARANTEES,
  HTTP_TLS_EGRESS_GUARANTEES,
  DESTINATION_BOUND_CREDENTIAL_GUARANTEES,
  CapabilityAdmissionError,
  CapabilityCredentialStore,
  CapabilityInvocationContext,
  canonicalizeCapabilityInvocationRequest,
  getCapabilityInvocationFeatureManifest,
  type ExactReaderGuarantee,
  type CapabilityHttpMethod,
  type CapabilityNetworkRule,
  type CapabilityNetworkAuthority,
  type CapabilityCredentialValidity,
  type CapabilityCredentialProjection,
  type CapabilityCredentialAuthority,
  type TrustedCapabilityCredential,
  type ExactReaderCeiling,
  type ExactReaderInvocationRequest,
  type ExactWriterGuarantee,
  type ExactWriterOperation,
  type ExactWriterCeiling,
  type ExactWriterInvocationRequest,
  type CapabilityCeiling,
  type CapabilityInvocationRequest,
  type CapabilityInvocationRuntimeOptions,
  type CapabilityEffectDecision,
  type CapabilityEffect,
  type CapabilityFilesystemEffect,
  type CapabilityNetworkEffect,
  type CapabilityCredentialEffect,
  type CapabilityTeardownEvidence,
  type CapabilityInvocationOutcome,
  type CapabilityInvocationEvidence,
  type CapabilityInvocationResult,
  type CanonicalCapabilityRequest,
  type CapabilityFeatureStatus,
  type CapabilityInvocationFeatureManifest,
} from "./capability-invocation.ts";
export {
  CAPABILITY_FEATURE_SCHEMA_VERSION,
  EXECUTION_IDENTITY_RETENTION_MS,
  getCapabilityEvidenceVerifierIdentity,
  probeCapabilityInvocationTeardown,
  verifyCapabilityInvocationEvidence,
  verifyCapabilityInvocationResult,
  type AuthenticatedEvidenceEvent,
  type CapabilityEvidenceDecision,
  type CapabilityEvidenceIntegrity,
  type CapabilityEvidenceVerificationOptions,
  type CapabilityEvidenceVerification,
} from "./invocation-evidence.ts";
export {
  SCOPED_RUNNER_GUARANTEES,
  ScopedRunnerInvocationContext,
  canonicalizeScopedRunnerInvocationRequest,
  type ScopedRunnerGuarantee,
  type ScopedRunnerCeiling,
  type ScopedRunnerInvocationRequest,
  type ScopedRunnerInvokeOptions,
  type ScopedRunnerFilesystemEffect,
  type ScopedRunnerProcessEvent,
  type ScopedRunnerInvocationEvidence,
  type ScopedRunnerInvocationResult,
  type ScopedRunnerResourceAccounting,
  type CanonicalScopedRunnerRequest,
} from "./scoped-runner.ts";
export {
  ADAPTIVESANDBOX_PIN_SCHEMA_VERSION,
  ADAPTIVESANDBOX_MATRIX_SCHEMA_VERSION,
  ADAPTIVESANDBOX_REPORT_SCHEMA_VERSION,
  REQUIRED_ADAPTIVESANDBOX_FIXTURE_CATEGORIES,
  QUALIFICATION_LATENCY_PHASES,
  parseAdaptiveSandboxConformancePin,
  verifyAdaptiveSandboxBundle,
  parseAdaptiveSandboxCompatibilityMatrix,
  parseAdaptiveSandboxQualificationReport,
  verifyQualificationInvocation,
  verifyControlledExecutionLink,
  summarizeQualificationSamples,
  capabilityFeatureManifestDigest,
  type AdaptiveSandboxFixtureCategory,
  type QualificationLatencyPhase,
  type QualificationStatus,
  type AdaptiveSandboxUnavailablePin,
  type AdaptiveSandboxReleasedPin,
  type AdaptiveSandboxConformancePin,
  type QemuQualificationIdentity,
  type AdaptiveSandboxQualificationIdentity,
  type PercentileSummary,
  type WorkloadPerformanceSummary,
  type QualificationReportSummary,
  type AdaptiveSandboxCompatibilityRow,
  type AdaptiveSandboxCompatibilityMatrix,
  type QualificationFixtureResult,
  type AdaptiveSandboxQualificationReport,
  type QualificationSample,
} from "./adaptivesandbox-conformance.ts";

// Server for running the sandbox
export { SandboxServer } from "./sandbox/server.ts";

// VFS (Virtual File System) providers
export {
  VirtualFileSystem,
  VirtualProvider,
  MemoryProvider,
  RealFSProvider,
  type VirtualFileHandle,
  type VfsStatfs,
  type VirtualFileSystemOptions,
} from "./vfs/node/index.ts";

export {
  SandboxVfsProvider,
  type VfsHooks,
  type VfsHookContext,
} from "./vfs/provider.ts";
export { ReadonlyProvider } from "./vfs/readonly.ts";
export { ReadonlyVirtualProvider } from "./vfs/readonly-virtual.ts";
export {
  ShadowProvider,
  createShadowPathPredicate,
  type ShadowProviderOptions,
  type ShadowWriteMode,
  type ShadowPredicate,
  type ShadowContext,
} from "./vfs/shadow.ts";
export {
  VirtualProviderClass,
  ERRNO,
  isWriteFlag,
  normalizeVfsPath,
  VirtualDirent,
  createVirtualDirStats,
  formatVirtualEntries,
} from "./vfs/utils.ts";
export {
  FsRpcService,
  type FsRpcMetrics,
  MAX_RPC_DATA,
} from "./vfs/rpc-service.ts";

// HTTP hooks for network policy
export {
  createHttpHooks,
  makePlaceholderFunc,
  BASE32_ALPHABET,
  BASE32_HEX_ALPHABET,
  BASE62_ALPHABET,
  BASE64URL_ALPHABET,
  HEX_ALPHABET,
  LOWERCASE_ALPHABET,
  UPPERCASE_ALPHABET,
  type CreateHttpHooksOptions,
  type CreateHttpHooksResult,
  type MakePlaceholderFuncOptions,
  type SecretDefinition,
  type SecretManager,
  type SecretManagerEntry,
  type SecretPlaceholderMode,
  type UpdateSecretOptions,
} from "./http/hooks.ts";

// Network types
export type {
  DnsMode,
  DnsOptions,
  SyntheticDnsHostMappingMode,
  HttpIpAllowInfo,
  HttpHooks,
  HttpFetch,
  TcpOptions,
} from "./qemu/net.ts";
export type {
  SshOptions,
  SshCredential,
  SshExecRequest,
  SshExecDecision,
  SshExecPolicy,
} from "./qemu/ssh.ts";
export { HttpRequestBlockedError } from "./http/utils.ts";
export {
  suggestHostsForSecret,
  type SecretHostSuggestion,
  type SuggestSecretHostsOptions,
} from "./secret-host-suggestions.ts";

// SSH helpers
export { getInfoFromSshExecRequest, type GitSshExecInfo } from "./ssh/exec.ts";

// Debug helpers
export {
  type DebugFlag,
  type DebugConfig,
  type DebugComponent,
  type DebugLogFn,
} from "./debug.ts";

// Ingress gateway
export {
  IngressGateway,
  GondolinListeners,
  IngressRequestBlockedError,
  parseListenersFile,
  serializeListenersFile,
  type IngressRoute,
  type EnableIngressOptions,
  type IngressAccess,
  type IngressGatewayHooks,
  type IngressAllowInfo,
  type IngressHeaders,
  type IngressHeaderValue,
  type IngressHeaderPatch,
  type IngressHookRequest,
  type IngressHookRequestPatch,
  type IngressHookResponse,
  type IngressHookResponsePatch,
} from "./ingress.ts";

// Session registry
export {
  registerSession,
  unregisterSession,
  listSessions,
  findSession,
  gcSessions,
  SessionIpcServer,
  connectToSession,
  type SessionInfo,
  type SessionEntry,
  type IpcClientCallbacks,
} from "./session-registry.ts";

// Asset management
export {
  ensureGuestAssets,
  getAssetVersion,
  getAssetDirectory,
  hasGuestAssets,
  loadGuestAssets,
  loadAssetManifest,
  type GuestAssets,
  type AssetManifest,
} from "./assets.ts";

// Local image store
export {
  getImageStoreDirectory,
  getImageObjectDirectory,
  importImageFromDirectory,
  resolveImageSelector,
  ensureImageSelector,
  listImageRefs,
  setImageRef,
  tagImage,
  type ImageArch,
  type ImageRefTargets,
  type LocalImageRef,
  type ImportedImage,
  type ResolvedImage,
} from "./images.ts";

// Build configuration and builder
export {
  type Architecture,
  type Distro,
  type ContainerRuntime,
  type OciPullPolicy,
  type BuildConfig,
  type AlpineConfig,
  type NixOSConfig,
  type ContainerConfig,
  type OciRootfsConfig,
  type RootfsConfig,
  type InitConfig,
  type RuntimeDefaultsConfig,
  type RootfsMode,
  getDefaultBuildConfig,
  getDefaultArch,
  validateBuildConfig,
  parseBuildConfig,
  serializeBuildConfig,
} from "./build/config.ts";

export {
  buildAssets,
  verifyAssets,
  type BuildOptions,
  type BuildResult,
} from "./build/index.ts";

export type { ExactWriterPublication } from "./capability-filesystem.ts";

export {
  HttpsInvocationContext,
  canonicalizeHttpsInvocationRequest,
  verifyHttpsInvocationResult,
  HTTPS_REQUEST_SCHEMA_VERSION,
  HTTPS_CEILING_SCHEMA_VERSION,
  HTTPS_EVIDENCE_SCHEMA_VERSION,
  HTTPS_POLICY_VERSIONS,
  type HttpsInvocationRequest,
  type HttpsInvocationCeiling,
  type HttpsInvocationResult,
  type HttpsInvocationEvidence,
  type HttpsInvocationRuntimeOptions,
} from "./https-invocation.ts";
