// Thin JS shim — actual logic in the native addon.
const { validate } = require('./native/addon.node');
module.exports = { validate };
