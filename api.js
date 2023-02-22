const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const axios = require("axios");
const cors = require('cors');
// const childProcess = require('child_process');

const config = require("./config.json");
const { Client, LocalAuth } = require("whatsapp-web.js");

process.title = "whatsapp-node-api";
global.client = new Client({
  authStrategy: new LocalAuth(),
  puppeteer: { 
    headless: true,
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--unhandled-rejections=strict",
      "--disable-dev-shm-usage",
      "--fast-start",
    ]
  },
});

global.authed = false;

const app = express();

const port = process.env.PORT || config.port;
//Set Request Size Limit 50 MB
app.use(bodyParser.json({ limit: "50mb" }));

app.use(cors());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

const generateQR = () => {
  console.log("Running Generate QR");
  client.on("qr", (qr) => {
    console.log("qr ", qr );
    fs.writeFileSync("./components/last.qr", qr);
  });
}

const selfRestart = () => {
  console.log("This is pid " + process.pid);
  setTimeout(function () {
      process.on("exit", function () {
          require("child_process").spawn(process.argv.shift(), process.argv, {
              cwd: process.cwd(),
              detached : true,
              stdio: "inherit"
          });
      });
      process.exit();
  }, 5000);
}

generateQR();
client.on("authenticated", () => {
  console.log("AUTH!");
  authed = true;

  try {
    fs.unlinkSync("./components/last.qr");
  } catch (err) {}
});

client.on("auth_failure", () => {
  console.log("AUTH Failed !");
  process.exit();
});

client.on("ready", () => {
  console.log("Client is ready!");
});

client.on("message", async (msg) => {
  if (config.webhook.enabled) {
    if (msg.hasMedia) {
      const attachmentData = await msg.downloadMedia();
      msg.attachmentData = attachmentData;
    }
    axios.post(config.webhook.path, { msg });
  }
});
client.on("disconnected", () => {
  console.log("disconnected");
  authed = false;

  setTimeout(() => {
    selfRestart();
    // process.exit(1);
  }, 500);
});
client.initialize();

// const chatRoute = require("./components/chatting");
// const groupRoute = require("./components/group");
// const authRoute = require("./components/auth");
// const contactRoute = require("./components/contact");
const puteriRoute = require("./components/puteri");

app.use(function (req, res, next) {
  console.log(req.method + " : " + req.path);
  next();
});
// app.use("/chat", chatRoute);
// app.use("/group", groupRoute);
// app.use("/auth", authRoute);
// app.use("/contact", contactRoute);
app.use("/puteri", puteriRoute);

app.listen(port, () => {
  console.log("Server Running Live on Port : " + port);
});
