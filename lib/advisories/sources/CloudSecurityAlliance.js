const git = require("../../git");
const util = require("util");
const exec = util.promisify(require('child_process').exec);
const fs = require('fs-extra');
const gsd = require("../parsers/gsd");
const { traverse, cache} = require("../util");
const path = require("path");

const KEY = 'CloudSecurityAlliance';

const fetch = async () => {
    console.log(`[${KEY}]\tInitializing cache...`);
    const cacheClear = cache.init(KEY);

    console.log(`[${KEY}]\tCloning...`);
    const { dir } = await git.clone('https://github.com/cloudsecurityalliance/gsd-database.git', 'origin/main');

    console.log(`[${KEY}]\tCleaning...`);
    await exec(`grep -nrlw . -e 'RESERVED' --null | xargs -0 -r rm`, { cwd: dir });

    const dest = await cacheClear;

    console.log(`[${KEY}]\tReading...`);
    await traverse(dir,async file => {
        const json = await fs.readJSON(file);
        try {
            await cache.save(KEY, gsd.parse(json, 'utf8'));
        } catch (ex) {
            if (ex.message === 'MISSING_ID') {
                console.warn(`[${KEY}]\tMISSING_ID: ${path.relative(dir, file)}`);
            } else {
                console.log(`[${KEY}]\tFailed to parse ${path.relative(dir, file)}`);
                console.error(`[${KEY}]\t`, ex);
            }
        }
    }, /\.json$/, ['.git', '.github', 'allowlist.json']);

    await git.clean(dir);

    console.log(`[${KEY}]\tDone.`);

    return dest;
};


module.exports = {
    fetch
}