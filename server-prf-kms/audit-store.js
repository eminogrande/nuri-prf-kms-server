const MAX_ENTRIES = 500;
const entries = [];

export function recordAuditEntry(entry) {
  // store a shallow copy to avoid external mutation
  entries.push({ ...entry });
  if (entries.length > MAX_ENTRIES) {
    entries.shift();
  }
}

export function getAuditEntries() {
  return entries.slice().reverse();
}
