const os = require('os');
const path = require('path');
const fs = require('fs-extra');
const simpleGit = require('simple-git');
const { mkdtemp } = require('fs/promises');

const getInfo = async (repo, extras) => {
    const { git, dir } = await clone(repo);
    const { all } = await git.tags();

    const remoteShowOutput = await git.remote(['show', 'origin']);
    const match = remoteShowOutput.match(/HEAD branch:\s+(.+?)[\r\n]/);
    const main = match?.[1];

    all.unshift(`origin/${main}`);
    if (Array.isArray(extras)) {
        for (const extra of extras) {
            if (!all.includes(extra)) all.unshift(extra);
        }
    }

    if (!Array.isArray(all) || all.length === 0) return [];
    const tags = await Promise.all(all.map(async tag => {
        const [timestamp, hash] = (await git.raw(['log', '-1', '--format=%ct#%H', tag]) || '').trim().split('#');
        return {tag, hash, timestamp: 1000 * parseInt(timestamp)};
    }));

    await fs.remove(dir);

    return tags;
};

const getTag = async (repo, tag, hash) => {
    try {
        const { git, dir } = await clone(repo, hash || tag);
        const [timestamp, remoteHash] = (await git.raw(['log', '-1', '--format=%ct#%H', hash || tag]) || '').trim().split('#');

        await fs.remove(dir);

        return { tag, hash: hash || remoteHash, timestamp: 1000 * parseInt(timestamp) };
    } catch (ex) {
        console.error(ex);
    }
};

const getHistorical = async (repo, branch) => {
    const WEEKS_1 = 1 * 7 * 24 * 3600;
    const WEEKS_2 = 2 * WEEKS_1;
    const WEEKS_4 = 4 * WEEKS_1;
    const WEEK_START = (new Date(2020, 5, 1, 0, 0, 0, 0)).getTime() / 1000;
    try {
        const data = new Map();
        const reduceResults = timeLength => line => {
            const [timestamp, hash] = line.trim().split('#');

            if (hash) {
                const intTimestamp = parseInt(timestamp);
                const periodStart = Math.floor((intTimestamp - WEEK_START) / timeLength) * timeLength / WEEKS_1;
                if (!data.has(periodStart)) {
                    data.set(periodStart, {
                        tag: branch,
                        hash,
                        timestamp: 1000 * intTimestamp,
                    });
                }
            }
        };

        const { git, dir } = await clone(repo);
        await git.fetch(['--unshallow']);
        (await git.raw(['log', '--since=\'1.5 year ago\'', '--until=\'6 months ago\'', '--format=%ct#%H', branch]))?.toString?.()
            .trim().split(/[\r\n]+/).forEach(reduceResults(WEEKS_4));
        (await git.raw(['log', '--since=\'6 months ago\'', '--until=\'2 months ago\'', '--format=%ct#%H', branch]))?.toString?.()
            .trim().split(/[\r\n]+/).forEach(reduceResults(WEEKS_2));
        (await git.raw(['log', '--since=\'2 months ago\'', '--format=%ct#%H', branch]))?.toString?.()
            .trim().split(/[\r\n]+/).forEach(reduceResults(WEEKS_1));

        await fs.remove(dir);

        return [...data.values()].sort((a, b) => a.timestamp - b.timestamp);
    } catch (ex) {
        console.error(ex);
    }
};

const clone = async (repo, tag) => {
    const cleanTag = tag ? tag.replace(/[\/\\]+/g, '-') + '-' : '';
    const dir = await mkdtemp(path.join(os.tmpdir(), 'repo-' + cleanTag));
    const git = simpleGit(dir);
    await git.init();
    await git.addRemote('origin', repo);
    await git.addConfig('extensions.partialClone', 'true');
    await git.fetch(['--filter=blob:none', '--tags', '--depth=1', 'origin']);
    if (tag) await git.checkout(tag, {'-b': tag});

    return { git, dir };
};

const clean = async dir => {
    return fs.remove(dir);
}

module.exports = {
    getHistorical,
    getInfo,
    getTag,
    clone,
    clean
}