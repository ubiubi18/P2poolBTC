import { allocate, burnAttachedPayment, hasString, readString, writeString } from "./idena_storage";

export { allocate };

// Minimal Idena WASM registry shape. P2Pool nodes still verify roots locally;
// this contract is only a public timestamp/data-availability anchor.

const SNAPSHOT_DAY_LEN = 10; // YYYY-MM-DD
const HEX_32_LEN = 64;
const MAX_DATA_REF_LEN = 256;

export function schemaVersion(): u16 {
  return 1;
}

export function snapshotDayPrefix(snapshotDay: string): string {
  return "snapshot:" + snapshotDay + ":";
}

export function snapshotKey(snapshotDay: string, scoreRoot: string): string {
  return snapshotDayPrefix(snapshotDay) + scoreRoot.toLowerCase();
}

export function isValidSnapshotRecord(
  snapshotDay: string,
  idenaHeight: u64,
  idenaBlockHash: string,
  identityRoot: string,
  scoreRoot: string,
  formulaVersion: u16,
  dataHashOrCid: string
): bool {
  return isValidSnapshotDay(snapshotDay)
    && idenaHeight > 0
    && isHex32(idenaBlockHash)
    && isHex32(identityRoot)
    && isHex32(scoreRoot)
    && formulaVersion > 0
    && isValidDataRef(dataHashOrCid);
}

export function putSnapshotRecord(
  snapshotDay: string,
  idenaHeight: u64,
  idenaBlockHash: string,
  identityRoot: string,
  scoreRoot: string,
  formulaVersion: u16,
  dataHashOrCid: string
): bool {
  if (
    !isValidSnapshotRecord(
      snapshotDay,
      idenaHeight,
      idenaBlockHash,
      identityRoot,
      scoreRoot,
      formulaVersion,
      dataHashOrCid
    )
  ) {
    return false;
  }

  let recordLine = canonicalRecordLine(
    snapshotDay,
    idenaHeight,
    idenaBlockHash.toLowerCase(),
    identityRoot.toLowerCase(),
    scoreRoot.toLowerCase(),
    formulaVersion,
    dataHashOrCid
  );
  let key = snapshotKey(snapshotDay, scoreRoot);
  let existing = readString(key);
  if (existing.length > 0) {
    return existing == recordLine;
  }
  if (!burnAttachedPayment()) {
    return false;
  }
  writeString(key, recordLine);
  return true;
}

export function hasSnapshotRecord(snapshotDay: string, scoreRoot: string): bool {
  if (!isValidSnapshotLookup(snapshotDay, scoreRoot)) {
    return false;
  }
  return hasString(snapshotKey(snapshotDay, scoreRoot));
}

export function getSnapshotRecordLine(snapshotDay: string, scoreRoot: string): string {
  if (!isValidSnapshotLookup(snapshotDay, scoreRoot)) {
    return "";
  }
  return readString(snapshotKey(snapshotDay, scoreRoot));
}

export function canonicalRecordLine(
  snapshotDay: string,
  idenaHeight: u64,
  idenaBlockHash: string,
  identityRoot: string,
  scoreRoot: string,
  formulaVersion: u16,
  dataHashOrCid: string
): string {
  return snapshotDay
    + "|"
    + idenaHeight.toString()
    + "|"
    + idenaBlockHash.toLowerCase()
    + "|"
    + identityRoot.toLowerCase()
    + "|"
    + scoreRoot.toLowerCase()
    + "|"
    + formulaVersion.toString()
    + "|"
    + dataHashOrCid;
}

function isValidSnapshotDay(value: string): bool {
  if (value.length != SNAPSHOT_DAY_LEN) {
    return false;
  }
  if (value.charCodeAt(4) != 45 || value.charCodeAt(7) != 45) {
    return false;
  }
  for (let i = 0; i < SNAPSHOT_DAY_LEN; i++) {
    if (i == 4 || i == 7) {
      continue;
    }
    if (!isAsciiDigit(value.charCodeAt(i))) {
      return false;
    }
  }
  let year = fourDigits(value, 0);
  let month = twoDigits(value, 5);
  let day = twoDigits(value, 8);
  return year > 0 && month >= 1 && month <= 12 && day >= 1 && day <= maxDayForMonth(year, month);
}

function isValidSnapshotLookup(snapshotDay: string, scoreRoot: string): bool {
  return isValidSnapshotDay(snapshotDay) && isHex32(scoreRoot);
}

function isHex32(value: string): bool {
  if (value.length != HEX_32_LEN) {
    return false;
  }
  for (let i = 0; i < value.length; i++) {
    if (!isAsciiHex(value.charCodeAt(i))) {
      return false;
    }
  }
  return true;
}

function isValidDataRef(value: string): bool {
  if (value.length == 0 || value.length > MAX_DATA_REF_LEN) {
    return false;
  }
  for (let i = 0; i < value.length; i++) {
    let code = value.charCodeAt(i);
    if (code < 33 || code > 126 || code == 124) {
      return false;
    }
  }
  return true;
}

function fourDigits(value: string, offset: i32): u32 {
  return <u32>(
    (value.charCodeAt(offset) - 48) * 1000
    + (value.charCodeAt(offset + 1) - 48) * 100
    + (value.charCodeAt(offset + 2) - 48) * 10
    + value.charCodeAt(offset + 3)
    - 48
  );
}

function twoDigits(value: string, offset: i32): u32 {
  return <u32>((value.charCodeAt(offset) - 48) * 10 + value.charCodeAt(offset + 1) - 48);
}

function maxDayForMonth(year: u32, month: u32): u32 {
  if (month == 2) {
    return isLeapYear(year) ? 29 : 28;
  }
  if (month == 4 || month == 6 || month == 9 || month == 11) {
    return 30;
  }
  return 31;
}

function isLeapYear(year: u32): bool {
  return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

function isAsciiDigit(code: i32): bool {
  return code >= 48 && code <= 57;
}

function isAsciiHex(code: i32): bool {
  return (code >= 48 && code <= 57)
    || (code >= 65 && code <= 70)
    || (code >= 97 && code <= 102);
}
