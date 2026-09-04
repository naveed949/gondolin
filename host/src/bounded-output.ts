import { Writable } from "node:stream";

class CollectingSink extends Writable {
  readonly chunks: Buffer[] = [];
  private readonly owner: BoundedOutput;

  constructor(owner: BoundedOutput) {
    super();
    this.owner = owner;
  }

  override _write(
    chunk: Buffer | string,
    encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
    this.owner.accept(this, data);
    callback();
  }
}

/** Paired stdout/stderr collector enforcing one combined byte ceiling */
export class BoundedOutput {
  readonly stdout = new CollectingSink(this);
  readonly stderr = new CollectingSink(this);
  overflowed = false;
  private accepted = 0;
  private readonly limit: number;
  private readonly abort: AbortController;
  private readonly redact: (value: string) => string;

  constructor(
    limit: number,
    abort: AbortController,
    redact: (value: string) => string = (value) => value,
  ) {
    this.limit = limit;
    this.abort = abort;
    this.redact = redact;
  }

  accept(sink: CollectingSink, data: Buffer): void {
    const remaining = Math.max(0, this.limit - this.accepted);
    if (remaining > 0) sink.chunks.push(data.subarray(0, remaining));
    this.accepted += Math.min(remaining, data.length);
    if (data.length > remaining && !this.overflowed) {
      this.overflowed = true;
      this.abort.abort();
    }
  }

  get stdoutText(): string {
    return this.redact(Buffer.concat(this.stdout.chunks).toString("utf8"));
  }

  get stderrText(): string {
    return this.redact(Buffer.concat(this.stderr.chunks).toString("utf8"));
  }

  get acceptedBytes(): number {
    return this.accepted;
  }
}
