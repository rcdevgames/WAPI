const router = require('express').Router();
const { MessageMedia, Location } = require("whatsapp-web.js");
const request = require('request')
const vuri = require('valid-url');
const fs = require('fs');
const { resolve } = require('path');
const QRCode = require('qrcode');

const getQR = async () => {
    var path = "components/last.qr";
    return new Promise((resolve, reject) => {
        fs.readFile(path, 'utf8', (err, qr) => {
            if (!err && qr) {
                resolve(qr)
            }else {
                resolve(null);
            }
        })
    })
}

const generateQR = async (text) => {
    return new Promise(async (resolve, reject) => {
        if (text == null) resolve(null);
        var result = await QRCode.toDataURL(text, {type: 'utf-8', error: 'H'})
        resolve(result);
    });
}

const checkAuth = async () => {
    return new Promise((resolve, reject) => {
        client.getState()
        .then((data) => {
            if (data) {
                resolve(data)
            }else {
                resolve(false)
            }
        })
        .catch(() => resolve(false))
    })
}

const checkNumber = async (phone) => {
    return client.isRegisteredUser(`${phone}@c.us`)
}

router.get("/auth", async (req, res) => {
    var auth = await checkAuth();
    if (auth) {
        res.send({ success: true, message: 'Sudah Tersambung', data: auth });
    }else {
        data = await getQR();
        qr_code = await generateQR(data)
        res.send({ success: false, message: `Mohon Scan QR.`, data: qr_code })
    }
});

router.get("/logout", async (req, res) => {
    var callback = { success: true, message: 'Sukses Logout' };
    try {
        await client.logout();
    } catch (error) {
        console.log(error)
        callback = { success: false, message: 'Gagal Logout' };
    }
    res.send(callback);
})

router.post("/send", async (req, res) => {
    const base64regex = /^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?$/;
    const phoneregex = /^(^\+62|62)(\d{3,4}-?){2}\d{3,4}$/;
    let phone = req.body.phone;
    let file = req.body.base64;
    let fileName = req.body.filename;
    var auth = await checkAuth();

    var callback = { success: true, message: 'Success' };

    if (!phoneregex.test(phone)) {
        callback = { success: false, message: 'Format Nomor HP salah (Ex: 628xxxxxxxx)' };
    } else if (!base64regex.test(file)) {
        callback = { success: false, message: 'Format File Base64 Salah' };
    }else if (!auth) {
        callback = { success: false, message: 'Tidak Dapat Mengirim Pesan, Mohon Scan Ulang QR' };
    }

    var valid = await checkNumber(phone);

    if (!valid) {
        callback = { success: false, message: 'Nomor Tidak terdaftar pada whatsapp' };
    }

    // Reformat Phone Number
    fix_phone = phone.replace("+","").split("-").join("");

    try {
        let media = new MessageMedia('application/pdf', file, fileName);
        var response = await client.sendMessage(`${phone}@c.us`, media)
        if (response.id.fromMe) {
            callback = { success: true, message: `MediaMessage successfully sent to ${phone}` };
        }
    } catch (err) {
        console.log(err);
        callback = { success: false, message: `Gagal mengirim pesan ke ${phone}`, error: err };
    }

    res.send(callback);
})

module.exports = router;