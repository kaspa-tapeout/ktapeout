#!/usr/bin/env node

/**
 * Verify that the helper binary and the runtime-loaded adapter registry agree.
 *
 * This is intentionally a read-only distribution check.  Source registration
 * and a JSON file are not enough: the binary used by an operator must report
 * the same executable adapter at runtime.  The child receives only the
 * platform variables required to start a native Windows executable plus the
 * explicit registry path; signing credentials are never forwarded.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";

const defaultBundle = process.env.KTAPEOUT_RELEASE_HELPER_BUNDLE;
const adapterId = "tn10-name-controller-release-v1";
const expectedPhases = ["prepare", "preflight", "execute", "reconcile"];

function argument(name, fallback) {
  const index = process.argv.indexOf(name);
  return index === -1 ? fallback : process.argv[index + 1];
}

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function fail(error_code, detail) {
  const result = {
    schema: "KTAPEOUT-HELPER-BUNDLE-RUNTIME-CHECK-V1",
    status: "FAIL",
    error_code,
    detail,
  };
  console.log(JSON.stringify(result, null, 2));
  process.exitCode = 1;
}

const bundleArgument = argument("--bundle", defaultBundle);
if (!bundleArgument) {
  fail("BUNDLE_ARGUMENT_REQUIRED", "Pass --bundle or set KTAPEOUT_RELEASE_HELPER_BUNDLE.");
}
const bundle = bundleArgument ? path.resolve(bundleArgument) : "";
const registry = path.resolve(
  argument(
    "--registry",
    bundle ? path.join(bundle, "config", "application-release-target-adapter-registry.json") : "",
  ),
);
const executable = path.join(bundle, "bin", os.platform() === "win32" ? "ktape.exe" : "ktape");

if (!bundle) {
  // The required-argument error has already been emitted above.
} else if (!fs.existsSync(registry)) {
  fail("REGISTRY_MISSING", registry);
} else if (!fs.existsSync(executable)) {
  fail("HELPER_BINARY_MISSING", executable);
} else {
  let registryDocument;
  try {
    registryDocument = JSON.parse(fs.readFileSync(registry, "utf8"));
  } catch (error) {
    fail("REGISTRY_INVALID", String(error));
  }

  if (registryDocument) {
    const env = {
      SystemRoot: process.env.SystemRoot,
      windir: process.env.windir,
      PATH: process.env.PATH,
      TEMP: process.env.TEMP,
      TMP: process.env.TMP,
      KTAPEOUT_RELEASE_ADAPTER_REGISTRY: registry,
    };
    const child = spawnSync(executable, ["release", "adapters"], {
      cwd: bundle,
      env,
      encoding: "utf8",
      windowsHide: true,
    });
    let observed;
    try {
      observed = JSON.parse((child.stdout || "").trim());
    } catch (error) {
      fail("HELPER_OUTPUT_INVALID", { exit_code: child.status, stderr: child.stderr, error: String(error) });
    }

    if (observed) {
      const adapter = observed?.data?.adapters?.find((entry) => entry.adapter_id === adapterId);
      const phases = adapter?.implemented_phases || [];
      const phaseMatch = JSON.stringify(phases) === JSON.stringify(expectedPhases);
      const ok =
        child.status === 0 &&
        observed.status === "PASS" &&
        adapter?.status === "HOST_FREE_READY" &&
        adapter?.current_platform_registered === true &&
        phaseMatch;
      const result = {
        schema: "KTAPEOUT-HELPER-BUNDLE-RUNTIME-CHECK-V1",
        status: ok ? "PASS" : "FAIL",
        error_code: ok ? null : "HELPER_REGISTRY_MISMATCH",
        bundle,
        registry,
        registry_sha256: sha256(registry),
        executable,
        executable_sha256: sha256(executable),
        adapter_id: adapterId,
        observed: {
          process_exit_code: child.status,
          tool_status: observed.status,
          adapter_status: adapter?.status || null,
          current_platform_registered: adapter?.current_platform_registered || false,
          implemented_phases: phases,
        },
      };
      console.log(JSON.stringify(result, null, 2));
      if (!ok) process.exitCode = 1;
    }
  }
}

