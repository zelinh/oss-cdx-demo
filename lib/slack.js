const fetch = require("node-fetch");
const config = require("./config");

const slack = config.get('notification.slack');

const send = async (subject, body) => {
    const resp = await fetch(slack.hook, {
        method: 'post',
        body: JSON.stringify({
            MSG_TITLE: subject,
            MSG_BODY: body
        }),
        headers: {'Content-Type': 'application/json'}
    });
    const data = await resp.text();
    console.log(data);
};

module.exports = {
    send,
}