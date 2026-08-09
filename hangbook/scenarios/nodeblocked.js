// A JS runtime hang that is visible at the kernel layer: a synchronous
// read on stdin, which the harness holds open and never writes.
const fs = require("fs");
console.log("READY " + process.pid);
fs.readFileSync(0);
