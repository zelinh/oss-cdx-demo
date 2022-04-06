const git = require("../../git");
const fs = require('fs-extra');
const github = require("../parsers/github");
const { traverse, cache } = require('../util');
const path = require("path");

const KEY = 'GitHubAdvisory';

const fetch = async () => {
    console.log(`[${KEY}]\tInitializing cache...`);
    const cacheClear = cache.init(KEY);

    console.log(`[${KEY}]\tCloning...`);
    const { dir } = await git.clone('https://github.com/github/advisory-database.git', 'origin/main');

    const dest = await cacheClear;

    console.log(`[${KEY}]\tReading...`);
    await traverse(dir,async file => {
        const json = await fs.readJSON(file);
        try {
            await cache.save(KEY, github.parse(json));
        } catch (ex) {
            if (ex.message === 'MISSING_ID') {
                console.warn(`[${KEY}]\tMISSING_ID: ${path.relative(dir, file)}`);
            } else {
                if (!/unreviewed/.test(file)) {
                    console.log(`[${KEY}]\tFailed to parse ${path.relative(dir, file)}`);
                    console.error(`[${KEY}]\t`, ex);
                }
            }
        }
    }, /\.json$/, ['.git', '.github']);

    await git.clean(dir);

    console.log(`[${KEY}]\tDone.`);

    return dest;
};


module.exports = {
    fetch
}