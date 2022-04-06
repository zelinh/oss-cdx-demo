const git = require("../../git");
const fs = require('fs-extra');
const YAML = require('js-yaml');
const gitlab = require("../parsers/gitlab");
const { traverse, cache } = require('../util');
const path = require("path");

const KEY = 'GitLabAdvisory';

const fetch = async () => {
    console.log(`[${KEY}]\tInitializing cache...`);
    const cacheClear = cache.init(KEY);

    console.log(`[${KEY}]\tCloning...`);
    const { dir } = await git.clone('https://gitlab.com/gitlab-org/security-products/gemnasium-db.git', 'origin/master');

    const dest = await cacheClear;

    console.log(`[${KEY}]\tReading...`);
    await traverse(dir,async file => {
        const yaml = YAML.load(await fs.readFile(file, 'utf8'));
        try {
            await cache.save(KEY, gitlab.parse(yaml));
        } catch (ex) {
            if (ex.message === 'MISSING_ID') {
                console.warn(`[${KEY}]\tMISSING_ID: ${path.relative(dir, file)}`);
            } else {
                console.log(`[${KEY}]\tFailed to parse ${path.relative(dir, file)}`);
                console.error(`[${KEY}]\t`, ex);
            }
        }
    }, /\.yml$/, ['.git', '.gitlab', '.gitlab-ci.yml']);

    await git.clean(dir);

    console.log(`[${KEY}]\tDone.`);

    return dest;
};


module.exports = {
    fetch
}