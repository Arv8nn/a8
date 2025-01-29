require('dotenv').config();
const express = require("express");
const { exec } = require('child_process');
const app = express();
app.use(express.json());
const commandToRun = "cd ~ && bash serv00keep.sh";
function runCustomCommand() {
    exec(commandToRun, function (err, stdout, stderr) {
        if (err) {
            console.log("Command execution error: " + err);
            return;
        }
        if (stderr) {
            console.log("Command execution standard error output: " + stderr);
        }
        console.log("Command execution successful:\n" + stdout);
    });
}
setInterval(runCustomCommand, 3 * 60 * 1000); // 3 分钟 = 3 * 60 * 1000 毫秒
app.get("/up", function (req, res) {
    runCustomCommand();
    res.type("html").send("<pre>Serv00 webpage keepalive starts：Serv00！UP！UP！UP！</pre>");
});
app.use((req, res, next) => {
    if (req.path === '/up') {
        return next();
    }
    res.status(404).send('Change the browser address to：http://name.name.serv00.net/up Only in this way can the Serv00 webpage keep-alive be started.');
});
app.listen(3000, () => {
    console.log("The server is started, listening port 3000");
    runCustomCommand();
});
