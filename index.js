const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const wa = require("wa-multi-session");

const app = express();

// Library
app.use(bodyParser.json({ limit: "50mb" }));
app.use(cors());
app.use(express.json())
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// WA Multi Session
wa.setCredentialsDir("puteri_credential");
wa.loadSessionsFromStorage();
wa.onConnected((sessionId) => {
    console.log("session connected :" + sessionId);
});
wa.onQRUpdated(({sessionId, qr}) => {
    console.log("session connected :" + sessionId);
    console.log("QRCODE :" + qr);
})

app.use((req, res, next) => {
    console.log(req.method + " : " + req.path);
    next();
});

// Routes
const puteriRoute = require("./api");
//-------------------------------------------------//
app.use("/puteri", puteriRoute);

// Runner
var messages = "Server Running Live on Port : 3000";
app.listen(3000, () => console.log(messages));