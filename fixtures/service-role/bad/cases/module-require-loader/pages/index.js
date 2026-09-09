// `module.require()` is a real Node module loader. Dropping every `require` preceded by a dot
// — added to stop `Array.from(",")` opening a specifier slot — took this with it, and the
// dependency below went unwalked: ok, exit 0, where the pre-tokeniser extractor caught it.
const { admin } = module.require("../lib/admin");

module.exports = function Page() {
  return admin;
};
