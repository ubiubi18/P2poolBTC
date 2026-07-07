import {
  allocate,
  canonicalRecordLine,
  getSnapshotRecordLine,
  hasSnapshotRecord,
  isValidSnapshotRecord,
  putSnapshotRecord,
} from "./index";

export { allocate };

const DAY = "2026-07-01";
const LEAP_DAY = "2028-02-29";
const INVALID_LEAP_DAY = "2026-02-29";
const BLOCK_HASH = "1111111111111111111111111111111111111111111111111111111111111111";
const IDENTITY_ROOT = "2222222222222222222222222222222222222222222222222222222222222222";
const SCORE_ROOT = "3333333333333333333333333333333333333333333333333333333333333333";
const OTHER_SCORE_ROOT = "4444444444444444444444444444444444444444444444444444444444444444";
const UNPAID_SCORE_ROOT = "5555555555555555555555555555555555555555555555555555555555555555";
const CID = "bafybeigdyrzt2qhxzn4c5v6xw7x3example";

export function smokeStrictDateValidation(): bool {
  return isValidSnapshotRecord(LEAP_DAY, 1, BLOCK_HASH, IDENTITY_ROOT, SCORE_ROOT, 1, CID)
    && !isValidSnapshotRecord(INVALID_LEAP_DAY, 1, BLOCK_HASH, IDENTITY_ROOT, SCORE_ROOT, 1, CID)
    && !isValidSnapshotRecord("2026-04-31", 1, BLOCK_HASH, IDENTITY_ROOT, SCORE_ROOT, 1, CID);
}

export function smokeRejectsAmbiguousDataRef(): bool {
  return !isValidSnapshotRecord(DAY, 1, BLOCK_HASH, IDENTITY_ROOT, SCORE_ROOT, 1, "cid|ambiguous");
}

export function smokeRequiresPaymentForNewRecord(): bool {
  return !putSnapshotRecord(DAY, 1, BLOCK_HASH, IDENTITY_ROOT, UNPAID_SCORE_ROOT, 1, CID)
    && !hasSnapshotRecord(DAY, UNPAID_SCORE_ROOT);
}

export function smokeStoresReadsAndRepeats(): bool {
  let expected = canonicalRecordLine(DAY, 1, BLOCK_HASH, IDENTITY_ROOT, SCORE_ROOT, 1, CID);
  return putSnapshotRecord(DAY, 1, BLOCK_HASH, IDENTITY_ROOT, SCORE_ROOT, 1, CID)
    && putSnapshotRecord(DAY, 1, BLOCK_HASH, IDENTITY_ROOT, SCORE_ROOT, 1, CID)
    && hasSnapshotRecord(DAY, SCORE_ROOT.toUpperCase())
    && getSnapshotRecordLine(DAY, SCORE_ROOT) == expected;
}

export function smokeRejectsSameRootConflict(): bool {
  return putSnapshotRecord(DAY, 2, BLOCK_HASH, IDENTITY_ROOT, OTHER_SCORE_ROOT, 1, CID)
    && !putSnapshotRecord(DAY, 2, BLOCK_HASH, IDENTITY_ROOT, OTHER_SCORE_ROOT, 1, "different-cid");
}

export function smokeRejectsInvalidLookups(): bool {
  return !hasSnapshotRecord("2026-99-99", SCORE_ROOT)
    && getSnapshotRecordLine(DAY, "not-a-root").length == 0;
}
