// Records what @agledger/verify-core's verifyAuditExport returns for every
// corpus export vector, unpinned and pinned on the export's own anchoredFrom,
// and the live dated-distrust export under four distrust entries, for
// tests/test_verify_export_parity.py to hold verify_export to field for
// field. Run from this repo's root against a built verify-core checkout at the
// version this package ports:
//
//   (cd ../verify-core && npm run build)
//   node scripts/record-verify-core-exports.mjs ../verify-core
//
// Re-record when verify-core's export walk changes, and say in the commit
// which verify-core commit the results came from.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const core = resolve(process.argv[2] ?? '../verify-core');
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
    evidenceBinding: r.evidenceBinding,
    unsignedProjectionFields: r.unsignedProjectionFields,
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
      notes: (r.keyTrust.notes ?? []).map((n) => ({ keyId: n.keyId, statementId: n.statementId, detail: n.detail })),
      accounted: r.keyTrust.accounted.map((n) => ({ keyId: n.keyId, statementId: n.statementId, detail: n.detail })),
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
  if (o.requireSuppliedKeys) options.requireSuppliedKeys = true;
  if (o.trustAnchors) options.trustAnchors = o.trustAnchors;
  const pins = [undefined];
  const anchoredFrom = doc.exportMetadata?.anchoredFrom;
  if (!o.trustAnchors && typeof anchoredFrom === 'string') pins.push([anchoredFrom]);
  for (const trustAnchors of pins) {
    const id = `${v.file}${trustAnchors ? '|pinned' : ''}${Object.keys(o).length ? `|${Object.keys(o).sort().join(',')}` : ''}`;
    runs[id] = { file: v.file, options: o, trustAnchors: trustAnchors ?? o.trustAnchors ?? null, result: project(verifyAuditExport(doc, trustAnchors ? { ...options, trustAnchors } : options)) };
  }
}

// A Server 2.0 export taken after a dated VAULT_DISTRUSTED_KEYS entry
// (its signingKeyWindows lists the distrusted key with distrustedFrom), pinned
// on its anchoredFrom alone and with a distrust entry at the Server's instant,
// a later one and an earlier one.
const DISTRUST_FILE = join('tests', 'fixtures', 'live-2.0.0', 'export-dated-distrust.json');
const distrustDoc = JSON.parse(readFileSync(DISTRUST_FILE, 'utf8'));
const pin = [distrustDoc.exportMetadata.anchoredFrom];
const distrustedKey = 'sha256:b649db0ec7c5c0fd921c2cb4d40466d91f4d98252dad2f7c0243851167b2d09e';
const distrust = {};
for (const [id, distrustedKeys] of [
  ['pin only', undefined],
  ['server instant', [`${distrustedKey}@2026-10-05T23:03:51.537314Z`]],
  ['later instant', [`${distrustedKey}@2026-10-05T23:04:00Z`]],
  ['earlier instant', [`${distrustedKey}@2026-10-05T23:03:48Z`]],
]) {
  const options = { trustAnchors: pin, ...(distrustedKeys ? { distrustedKeys } : {}) };
  distrust[id] = { trustAnchors: pin, distrustedKeys: distrustedKeys ?? null, result: project(verifyAuditExport(distrustDoc, options)) };
}

// Server 2.2 exports taken with ?evidence=true, pinned on their anchoredFrom:
// unedited, then with one inlined body edited or misplaced. Each edit is
// recorded as data (the entry by type, or by index, and the value set on its
// `evidence`) so the Python test applies exactly the same one.
const EVIDENCE_DIR = join('tests', 'fixtures', 'live-2.2.0');
const evidenceCases = {
  'cleartext, unedited': { file: 'export-evidence.json', edit: null },
  'completion body edited': { file: 'export-evidence.json', edit: { at: 'COMPLETION_SUBMITTED', merge: { summary: 'edited' } } },
  'dispute body edited': { file: 'export-evidence.json', edit: { at: 'DISPUTE_EVIDENCE', merge: { doc: 'invoice-999' } } },
  'body on an entry that binds none': { file: 'export-evidence.json', edit: { at: 0, set: { summary: 'attached where nothing signs it' } } },
  'body is an array': { file: 'export-evidence.json', edit: { at: 'DISPUTE_EVIDENCE', set: ['x'] } },
  'body is a string': { file: 'export-evidence.json', edit: { at: 'COMPLETION_SUBMITTED', set: 'x' } },
  'encrypted-mode completion': { file: 'export-encrypted-evidence.json', edit: null },
};
const evidence = {};
for (const [id, c] of Object.entries(evidenceCases)) {
  const doc = JSON.parse(readFileSync(join(EVIDENCE_DIR, c.file), 'utf8'));
  if (c.edit) {
    const entry = typeof c.edit.at === 'number' ? doc.entries[c.edit.at] : doc.entries.find((e) => e.entryType === c.edit.at);
    entry.evidence = c.edit.merge ? { ...entry.evidence, ...c.edit.merge } : c.edit.set;
  }
  const trustAnchors = [doc.exportMetadata.anchoredFrom];
  evidence[id] = { ...c, trustAnchors, result: project(verifyAuditExport(doc, { trustAnchors })) };
}

const out = { verifyCore: `${pkg.version} @ ${sha}`, runs, distrust, evidence };
writeFileSync(join('tests', 'fixtures', 'verify-core-exports.json'), JSON.stringify(out, null, 1) + '\n');
console.error(`recorded ${Object.keys(runs).length} runs from @agledger/verify-core ${out.verifyCore}`);
