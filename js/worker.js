/**
 * Web Worker executing PII detection, validation, and redaction off the UI thread.
 */

import { runSanitization } from "./pipeline.js";
import { createPseudonymMapper } from "./redactors.js";

self.addEventListener("message", (event) => {
  const {
    requestId,
    text,
    format,
    enabledTypes,
    mode,
    typedFullMask,
    persistMapping,
    mapperEntries,
  } = event.data || {};

  try {
    const mapper = createPseudonymMapper(persistMapping ? mapperEntries : []);
    if (persistMapping) mapper.beginRun();

    const result = runSanitization(text, {
      format,
      enabledTypes,
      mode,
      typedFullMask,
      mapper,
    });

    self.postMessage({
      requestId,
      ok: true,
      result: {
        format: result.format,
        sanitizedText: result.sanitizedText,
        entities: result.entities,
        replacements: result.replacements,
        rejected: result.rejected,
        mapperEntries: result.mapper.entries(),
        csvStats: result.csvStats,
        durationMs: result.durationMs,
      },
    });
  } catch (err) {
    self.postMessage({
      requestId,
      ok: false,
      error: err?.message || "Worker sanitization failed.",
    });
  }
});
