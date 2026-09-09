// A JavaScript project importing an explicit `.js`. A same-named `.ts` sits beside it and is
// clean; `lib/admin.js` — the module Node actually loads — holds the key. Ordering the
// candidate list put the `.ts` substitution first, so the clean file was scanned and this
// returned ok, exit 0. Whichever candidate is second gets skipped, so both are walked now.
const { admin } = require("../lib/admin.js");

module.exports = function Page() {
  return admin;
};
