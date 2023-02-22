const router = require("express").Router();
const fs = require("fs");

router.get("/checkauth", async (req, res) => {
  client
    .getState()
    .then((data) => {
      if (data) {
        res.send({ success: true, message: data });
      }else {
        res.send({ success: false, message: `Disconnected` });
      }
    })
    .catch((err) => {
      if (err) {
        res.send({ success: false, message: `Disconnected` });
      }
    });
});

router.get("/getqr", async (req, res) => {
  client
    .getState()
    .then((data) => {
      if (data) {
        res.send({ success: true, message: `Already Authenticated` });
      } else {
        res.send({ success: false, message: `Please Scan QR First.`, data: sendQr() });
      }
    })
    .catch(() => res.send({ success: false, message: `Please Scan QR First.`, data: sendQr() }));
});

function sendQr(res=null) {
  fs.readFile("components/last.qr", (err, last_qr) => {
    if (!err && last_qr) {
      return last_qr
      // var page = `
      //               <html>
      //                   <body>
      //                       <script type="module">
      //                       </script>
      //                       <div id="qrcode"></div>
      //                       <script type="module">
      //                           import QrCreator from "https://cdn.jsdelivr.net/npm/qr-creator/dist/qr-creator.es6.min.js";
      //                           let container = document.getElementById("qrcode");
      //                           QrCreator.render({
      //                               text: "${last_qr}",
      //                               radius: 0.5, // 0.0 to 0.5
      //                               ecLevel: "H", // L, M, Q, H
      //                               fill: "#536DFE", // foreground color
      //                               background: null, // color or null for transparent
      //                               size: 256, // in pixels
      //                           }, container);
      //                       </script>
      //                   </body>
      //               </html>
      //           `;
      // res.write(page);
      // res.end();
    }
  });
}

module.exports = router;
