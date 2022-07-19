const nodemailer = require("nodemailer");
const config = require("./config");

const smtp = config.get('email');

const send = async (subject, body) => {
    const transporter = nodemailer.createTransport({
        host: smtp.host,
        port: smtp.port,
        secure: true,
        auth: {
            user: smtp.username,
            pass: smtp.password
        }
    });

    const info = await transporter.sendMail({
        from: 'Advisories <advisories@aws.barahmand.com>',
        to: smtp.to,
        subject: subject, //"Summary of vulnerabilities for the week of",
        html: body,
        dkim: {
            domainName: smtp.dkim.domain,
            keySelector: smtp.dkim.selector,
            privateKey: smtp.dkim.key
        }
    });

    if (typeof info?.response === 'string') {
        if (/^250/.test(info.response)) return true;

        throw info.response;
    }

    console.log(info);
    throw "Unknown email error";

};

module.exports = {
    send,
}