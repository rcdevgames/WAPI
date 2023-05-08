const router = require("express").Router();
const wa = require("wa-multi-session");

const PUTERI_SESSION = "PUTERI_SESSION";

router.get("/auth", async (req, res) => {
    const session = await wa.startSession();
    // const session = wa.getAllSession();
    // const session = wa.getSession(PUTERI_SESSION);
    res.send({session});
});


module.exports = router;