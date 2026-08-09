const net = require("net");
const srv = net.createServer(() => {});
srv.listen(0, () => {
  console.log("READY " + process.pid);
  setInterval(() => {}, 1e9);
});
