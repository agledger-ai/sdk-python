// Records what @agledger/verify-core's verifyAuditExport returns for every
// corpus export vector, unpinned and pinned on the export's own anchoredFrom,
// for tests/test_verify_export_parity.py to hold verify_export to field for
// field. Run from this repo's root against a built verify-core checkout at the
// version this package ports:
//
//   (cd ~/projects/agledger-verify-core && npm run build)
//   node scripts/record-verify-core-exports.mjs ~/projects/agledger-verify-core
//
// Re-record when verify-core's export walk changes, and say in the commit
// which verify-core commit the results came from.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const core = resolve(process.argv[2] ?? join(process.env.HOME ?? '', 'projects', 'agledger-verify-core'));
const { verifyAuditExport } = await import(pathToFileURL(join(core, 'dist', 'index.js')).href);
const pkg = JSON.parse(readFileSync(join(core, 'package.json'), 'utf8'));
let sha = 'unknown';
try { sha = execFileSync('git', ['-C', core, 'rev-parse', '--short=8', 'HEAD'], { encoding: 'utf8' }).trim(); } catch { /* not a git checkout */ }

const CORPUS = resolve('testdata', 'conformance');
const manifest = JSON.parse(readFileSync(join(CORPUS, 'manifest-export.json'), 'utf8'));
const json = (rel) => JSON.parse(readFileSync(join(CORPUS, rel), 'utf8'));
const unwrapKeys = (raw) => (raw && typeof raw === 'object' && !Array.isArray(raw) && Array.isArray(raw.data) ? raw.data : raw);

/** The fields verify_export ports, in verify-core's shape. */
function project(r) {
  return {
    valid: r.valid,
    totalEntries: r.totalEntries,
    verifiedEntries: r.verifiedEntries,
    brokenAt: r.brokenAt ? { position: r.brokenAt.position, code: r.brokenAt.code, detail: r.brokenAt.detail ?? null } : null,
    entries: r.entries.map((e) => ({ position: e.position, valid: e.valid, code: e.code ?? null, detail: e.detail ?? null, signature: e.signature ?? null })),
    signatureCoverage: r.signatureCoverage,
    keyProvenance: r.keyProvenance,
    optionalChecks: r.optionalChecks,
    agentSignatures: r.agentSignatures,
    keyTrust: {
      status: r.keyTrust.status,
      detail: r.keyTrust.detail,
      anchors: r.keyTrust.anchors,
      anchoredFrom: r.keyTrust.anchoredFrom,
      anchoredFromPinned: r.keyTrust.anchoredFromPinned,
      order: r.keyTrust.order,
      anchoredKeyIds: r.keyTrust.anchoredKeyIds,
      unanchoredKeyIds: r.keyTrust.unanchoredKeyIds,
      undecidedKeyIds: r.keyTrust.undecidedKeyIds,
      findings: r.keyTrust.findings.map((f) => ({ code: f.code, keyId: f.keyId, statementId: f.statementId, detail: f.detail })),
    },
  };
}

const runs = {};
for (const v of manifest.vectors) {
  const o = v.options ?? {};
  const doc = json(v.file);
  const options = {};
  if (o.keysFile) options.publicKeys = unwrapKeys(json(o.keysFile));
  if (o.agentKeysFile) options.agentKeys = json(o.agentKeysFile);
  if (o.requireKeyId) options.requireKeyId = o.requireKeyId;
  if (o.requireOutOfBandKeys) options.requireSuppliedKeys = true;
  if (o.trustAnchors) options.trustAnchors = o.trustAnchors;
  const pins = [undefined];
  const anchoredFrom = doc.exportMetadata?.anchoredFrom;
  if (!o.trustAnchors && typeof anchoredFrom === 'string') pins.push([anchoredFrom]);
  for (const trustAnchors of pins) {
    const id = `${v.file}${trustAnchors ? '|pinned' : ''}${Object.keys(o).length ? `|${Object.keys(o).sort().join(',')}` : ''}`;
    runs[id] = { file: v.file, options: o, trustAnchors: trustAnchors ?? o.trustAnchors ?? null, result: project(verifyAuditExport(doc, trustAnchors ? { ...options, trustAnchors } : options)) };
  }
}

const out = { verifyCore: `${pkg.version} @ ${sha}`, runs };
writeFileSync(join('tests', 'fixtures', 'verify-core-exports.json'), JSON.stringify(out, null, 1) + '\n');
console.error(`recorded ${Object.keys(runs).length} runs from @agledger/verify-core ${out.verifyCore}`);
