import { createHash, randomUUID } from "node:crypto";

export type HttpsObservationPolicy = Readonly<{
  url: string;
  method: "GET" | "HEAD";
  /** Maximum decoded response entity size in `bytes` */
  maxResponseBytes: number;
  /** Deadline from mediator admission in `ms` */
  timeoutMs: number;
}>;

export type HttpsConnectedPeer = Readonly<{
  connectionId: string;
  peerAddress: string;
  peerPort: number;
  tlsHostname: string;
  tlsVerified: true;
}>;

export type HttpsSettlement =
  | "not_started"
  | "pending"
  | "complete"
  | "timeout"
  | "overflow"
  | "transport_failure"
  | "redirect_denied"
  | "request_denied";
export type HttpsFailure = Exclude<
  HttpsSettlement,
  "not_started" | "pending" | "complete"
>;
export type HttpsObservedResponse = Readonly<{
  status: number;
  /** Canonical base64 of the decoded upstream entity */
  bodyBase64: string;
  bodyBytes: number;
  /** SHA-256 of decoded entity bytes with `sha256:` prefix */
  bodyDigest: string;
}>;

/** Internal one-request state owned by the dedicated controller and transport. */
export class HttpsObservation {
  readonly policy: HttpsObservationPolicy;
  readonly requestId = randomUUID();
  #abort = new AbortController();
  #timer?: ReturnType<typeof setTimeout>;
  #started?: number;
  #ended?: number;
  #settlement: HttpsSettlement = "not_started";
  #connection: HttpsConnectedPeer | null = null;
  #response: HttpsObservedResponse | null = null;
  #receivedBytes = 0;
  #candidates: Readonly<{ address: string; family: 4 | 6 }>[] = [];

  constructor(policy: HttpsObservationPolicy) {
    const url = new URL(policy.url);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.hash ||
      url.href !== policy.url ||
      !["GET", "HEAD"].includes(policy.method) ||
      !Number.isSafeInteger(policy.maxResponseBytes) ||
      policy.maxResponseBytes <= 0 ||
      !Number.isSafeInteger(policy.timeoutMs) ||
      policy.timeoutMs <= 0 ||
      policy.timeoutMs > 2_147_483_647
    )
      throw new Error("invalid HTTPS observation policy");
    this.policy = Object.freeze({ ...policy });
  }

  get signal(): AbortSignal {
    return this.#abort.signal;
  }

  begin(url: string, method: string, hasBody: boolean): void {
    if (
      this.#settlement !== "not_started" ||
      url !== this.policy.url ||
      method !== this.policy.method ||
      hasBody
    ) {
      this.fail("request_denied");
      throw new Error("HTTPS request differs from one-shot authority");
    }
    this.#started = performance.now();
    this.#settlement = "pending";
    this.#timer = setTimeout(() => this.fail("timeout"), this.policy.timeoutMs);
    this.#timer.unref();
  }

  assertPending(): void {
    this.signal.throwIfAborted();
    if (
      this.#started !== undefined &&
      performance.now() - this.#started >= this.policy.timeoutMs
    )
      this.fail("timeout");
    this.signal.throwIfAborted();
    if (this.#settlement !== "pending")
      throw new Error("HTTPS observation is not pending");
  }

  resolutionCandidate(record: { address: string; family: 4 | 6 }): void {
    this.assertPending();
    this.#candidates.push(Object.freeze({ ...record }));
  }

  connected(record: HttpsConnectedPeer): void {
    this.assertPending();
    if (
      this.#connection ||
      !record.connectionId ||
      !record.peerAddress ||
      record.tlsVerified !== true ||
      record.tlsHostname !== new URL(this.policy.url).hostname ||
      record.peerPort !== Number(new URL(this.policy.url).port || 443)
    ) {
      this.fail("transport_failure");
      throw new Error("invalid or repeated HTTPS peer observation");
    }
    this.#connection = Object.freeze({ ...record });
  }

  received(bytes: number): void {
    this.assertPending();
    this.#receivedBytes += bytes;
    if (this.#receivedBytes > this.policy.maxResponseBytes) {
      this.fail("overflow");
      throw new Error("HTTPS decoded response exceeds authority");
    }
  }

  complete(status: number, body: Buffer): void {
    this.assertPending();
    if (
      !this.#connection ||
      !Number.isInteger(status) ||
      status < 200 ||
      status > 599 ||
      body.length !== this.#receivedBytes ||
      body.length > this.policy.maxResponseBytes
    ) {
      this.fail("transport_failure");
      throw new Error("incomplete HTTPS response provenance");
    }
    this.#response = Object.freeze({
      status,
      bodyBase64: body.toString("base64"),
      bodyBytes: body.length,
      bodyDigest: `sha256:${createHash("sha256").update(body).digest("hex")}`,
    });
    this.#settlement = "complete";
    this.#ended = performance.now();
    clearTimeout(this.#timer);
  }

  fail(reason: HttpsFailure): void {
    // A later forbidden attempt invalidates even a previously complete response.
    if (!["pending", "not_started", "complete"].includes(this.#settlement))
      return;
    this.#settlement = reason;
    this.#response = null;
    this.#ended = performance.now();
    clearTimeout(this.#timer);
    this.#abort.abort(new Error(`HTTPS ${reason}`));
  }

  finish(): void {
    if (this.#settlement === "pending" || this.#settlement === "not_started")
      this.fail("transport_failure");
    clearTimeout(this.#timer);
  }

  snapshot() {
    return Object.freeze({
      requestId: this.requestId,
      urlDigest: `sha256:${createHash("sha256").update(this.policy.url).digest("hex")}`,
      method: this.policy.method,
      maxResponseBytes: this.policy.maxResponseBytes,
      timeoutMs: this.policy.timeoutMs,
      settlement: this.#settlement,
      elapsedMs:
        this.#started === undefined
          ? null
          : (this.#ended ?? performance.now()) - this.#started,
      receivedBytes: this.#receivedBytes,
      connection: this.#connection,
      response: this.#response,
      resolutionCandidates: Object.freeze([...this.#candidates]),
    });
  }
}
