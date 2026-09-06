import dns from "node:dns";
import net from "node:net";
import tls from "node:tls";
import { randomUUID } from "node:crypto";
import { buildConnector } from "undici";
import { isPublicAddress } from "../public-address.ts";

/** Internal observer installed by the dedicated controller, never guest input */
export type HttpsConnectorObservation = {
  readonly signal: AbortSignal;
  resolutionCandidate(record: { address: string; family: 4 | 6 }): void;
  connected(record: {
    connectionId: string;
    peerAddress: string;
    peerPort: number;
    tlsHostname: string;
    tlsVerified: true;
  }): void;
  fail(reason: "transport_failure" | "request_denied"): void;
};

type Destination = { hostname: string; port: number; protocol: "http" | "https" };
type ConnectorFactory = (options: buildConnector.BuildOptions) => buildConnector.connector;

/** Reject process-wide trust overrides rather than admitting a different trust root */
export function assertDefaultHttpsTrust(): void {
  const environmentOverrides = [
    "NODE_TLS_REJECT_UNAUTHORIZED", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR",
    "NODE_USE_SYSTEM_CA",
  ];
  if (environmentOverrides.some((key) => process.env[key] !== undefined) ||
      /--(?:use-(?:openssl|system|bundled)-ca|openssl-config|tls-cipher-list)/.test(
        `${process.env.NODE_OPTIONS ?? ""} ${process.execArgv.join(" ")}`,
      )) {
    throw new Error("HTTPS profile does not admit process TLS trust overrides");
  }
}

export function createValidatedHttpsConnector(
  destination: Destination,
  observation: HttpsConnectorObservation,
): buildConnector.connector {
  assertDefaultHttpsTrust();
  return guardHttpsConnector(destination, observation, buildConnector);
}

/** Internal construction seam; production always uses Undici's default connector */
export function guardHttpsConnector(
  destination: Destination,
  observation: HttpsConnectorObservation,
  factory: ConnectorFactory,
): buildConnector.connector {
  const { hostname, port } = destination;
  let attempted = false;
  // Passing the same signal into tls.connect closes a socket even during DNS/TLS.
  const connector = factory({
    rejectUnauthorized: true,
    maxCachedSessions: 0,
    allowH2: false,
    autoSelectFamily: false,
    signal: observation.signal,
    lookup(name, options, callback) {
      if (observation.signal.aborted || name !== hostname) {
        callback(new Error("HTTPS lookup denied"), "", 4);
        return;
      }
      dns.lookup(name, { ...options, all: false }, (error, address, family) => {
        if (observation.signal.aborted) {
          callback(new Error("HTTPS lookup cancelled"), "", 4);
          return;
        }
        if (error) { callback(error, "", 4); return; }
        try {
          if ((family !== 4 && family !== 6) || !isPublicAddress(address)) {
            throw new Error("HTTPS resolution candidate is not public");
          }
          observation.resolutionCandidate({ address, family });
          if (observation.signal.aborted) throw new Error("HTTPS lookup cancelled");
          callback(null, address, family);
        } catch (error) {
          callback(error as Error, "", 4);
        }
      });
    },
  });
  return (options, callback) => {
    if (attempted || observation.signal.aborted ||
        (net.isIP(hostname) !== 0 && !isPublicAddress(hostname)) || destination.protocol !== "https" ||
        options.protocol !== "https:" || options.hostname !== hostname ||
        Number(options.port || 443) !== port || options.httpSocket || options.localAddress ||
        (options.servername && options.servername !== hostname)) {
      observation.fail("request_denied");
      callback(new Error("HTTPS connection attempt denied"), null);
      return;
    }
    attempted = true;
    let completed = false;
    let socket: net.Socket | undefined;
    const finishError = (error: Error) => {
      socket?.destroy();
      if (completed) return;
      completed = true;
      observation.signal.removeEventListener("abort", abort);
      observation.fail("transport_failure");
      callback(error, null);
    };
    const abort = () => finishError(new Error("HTTPS connection cancelled"));
    observation.signal.addEventListener("abort", abort, { once: true });
    try {
      connector({ ...options, servername: net.isIP(hostname) ? undefined : hostname }, (error, connected) => {
        if (completed || observation.signal.aborted) {
          connected?.destroy();
          if (!completed) abort();
          return;
        }
        if (error) { finishError(error); return; }
        socket = connected;
        try {
          if (!(connected instanceof tls.TLSSocket) || connected.destroyed ||
              connected.authorized !== true || !connected.remoteAddress ||
              !isPublicAddress(connected.remoteAddress) || connected.remotePort !== port ||
              (!net.isIP(hostname) && connected.servername !== hostname) ||
              tls.checkServerIdentity(hostname, connected.getPeerCertificate())) {
            throw new Error("HTTPS connected peer or TLS identity verification failed");
          }
          observation.connected(Object.freeze({
            connectionId: randomUUID(), peerAddress: connected.remoteAddress,
            peerPort: connected.remotePort, tlsHostname: hostname, tlsVerified: true as const,
          }));
          if (observation.signal.aborted) throw new Error("HTTPS connection cancelled");
          completed = true;
          observation.signal.removeEventListener("abort", abort);
          callback(null, connected);
        } catch (error) { finishError(error as Error); }
      });
    } catch (error) { finishError(error as Error); }
  };
}
