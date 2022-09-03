const { promisify } = require('util');
const fs = require("fs-extra");
const { parentPort } = require('worker_threads');
const bom = require("@AMoo-Miki/cdxgen");
const OpenSearch = require("../opensearch");
const git = require("../git");
const exec = promisify(require('child_process').exec);
const { mkdtemp } = require('fs/promises');
const path = require("path");
const os = require("os");
const config = require("../config");
const { containsProject } = require("../opensearch");

const indices = config.get('opensearch.indices');

/**
 *
 * @param {Object.<string, (Object|string|number|Array<string>)>} project
 * @returns {Promise<void>}
 */
const run = async project => {
    if (!project) return;

    const logKey = `${project.name} @ ${project.tag} ${project.hash ? '#' + project.hash : ''}`;
    console.log(`[${logKey}]\tWorking on SBOM...`);

    if (await containsProject(project)) {
        console.log(`[${logKey}]\tSkipping #${project.hash}`);
        return;
    }

    // Execution timestamp
    const now = Date.now();
    const { dir, hash } = await git.clone(project.repo, project.tag, project.hash);

    if (!project.hash) {
        project.hash = hash;
        if (await containsProject(project)) {
            console.log(`[${logKey}]\tSkipping #${project.hash}`);
            return;
        }
    }

    const lockId = await OpenSearch.lockProgressState(project, 'sbom');
    if (lockId) {
        console.log(`[${logKey}]\tAcquired lock ${lockId}`);
    } else {
        console.log(`[${logKey}]\tUnable to acquire lock`);
        return;
    }

    try {
        // Install the project
        if (Array.isArray(project.install) && project.install.length) {
            const installCacheDir = await mkdtemp(path.join(os.tmpdir(), 'cache-'));

            for await (const cmd of project.install) {
                console.log(`[${logKey}]\tRunning:`, cmd);
                let stdout, stderr;
                try {
                    ({ stdout, stderr } = await exec(`bash -c ". $NVM_DIR/nvm.sh; ${cmd}"`, {
                        cwd: dir,
                        maxBuffer: 10 * 1024 * 1024,
                        env: {
                            ...process.env,
                            YARN_CACHE_FOLDER: installCacheDir,
                            GOPATH: installCacheDir,
                        }
                    }));
                } catch (ex) {
                    if (stdout) console.log(`[${logKey}]\tOutput:`, stdout);
                    if (stderr) console.error(`[${logKey}]\tError:`, stderr);
                    throw ex;
                }
            }
        }

        const roots = Array.isArray(project.roots)
            ? project.roots.map(root => path.join(dir, root))
            : [dir];

        const records = [];
        const purls = new Set();
        const addRecord = (rec, relativeRoot) => {
            const res = {
                name: (rec.group ? rec.group + '/' : '') + rec.name,
                version: rec.version,
                purl: rec.purl,
                scope: rec.scope,
                ecosystem: rec.supplier,
                origin: relativeRoot
                    ? Array.isArray(rec._src)
                        ? rec._src.map(src => path.join(relativeRoot, src))
                        : path.join(relativeRoot, rec._src)
                    : rec._src,
            };

            if (Array.isArray(rec.licenses)) {
                const licenses = rec.licenses
                    .map(lic => lic.license?.id)
                    .filter(lic => (lic && typeof lic === 'string'));

                if (licenses.length) res.licenses = licenses;
            } else if (rec.licenses && typeof rec.licenses !== 'string') {
                const license = rec.licenses.license?.id;
                if (license && typeof license === 'string') res.licenses = [license];
            }

            records.push(res);
        };

        for (let root of roots) {
            let rel = path.relative(dir, root);
            console.log(`[${logKey}]\tGenerating SBOM${rel ? ` in ${rel}` : ''}...`);

            // Generate SBOM
            const bomNSData = await bom.createBom(root, {
                dev: true,
                multiProject: true,
                depth: 100,
                installDeps: true,
            });
            console.log(`[${logKey}]\t${bomNSData.bomJson.components.length} components identified${rel}`);

            // Transform SBOM to the storage structure
            let hasJava = false
            bomNSData.bomJson.components.forEach(rec => {
                if (rec.purl) {
                    if (purls.has(rec.purl)) return;

                    if (rec.purl?.startsWith?.('pkg:maven/')) hasJava = true;
                    purls.add(rec.purl);
                }

                addRecord(rec, rel);
            });

            if (hasJava) {
                const bomJData = await bom.createBom(dir, {
                    dev: true,
                    multiProject: false,
                    projectType: 'java',
                    depth: 100,
                    installDeps: true,
                    gradleMultiMode: true,
                });

                if (bomJData) {
                    console.log(`[${logKey}]\t${bomJData.bomJson.components.length} additional components identified${rel}`);

                    bomJData.bomJson.components.forEach(rec => {
                        if (rec.purl) {
                            if (purls.has(rec.purl)) return;
                            purls.add(rec.purl);
                        }

                        addRecord(rec, rel);
                    });
                }
            }
        }

        // Clean cache
        await fs.remove(dir);

        if (records.length === 0) {
            console.error(`[${logKey}]\tFailed to generate SBOM; bailing out.`);
        } else {
            // Save records
            console.log(`[${logKey}]\tIndexing...`);
            await OpenSearch.indexDoc(indices.sboms, {
                project: {
                    name: project.name,
                    repo: project.repo,
                    tag: project.tag,
                    hash: project.hash,
                },
                packages: records,
                timestamp: {
                    commit: project.timestamp,
                    scan: now
                },
            });

            console.log(`[${logKey}]\tCompleted indexing`);
        }
    } catch (ex) {
        await OpenSearch.releaseProgressState(lockId, 'sbom', 'failed');
        throw ex;
    } finally {
        console.log(`[${logKey}]\tReleasing lock ${lockId}`);
        await OpenSearch.releaseProgressState(lockId, 'sbom', 'done');
    }
};

parentPort.on('message', async project => {
    await run(project);
    parentPort.postMessage('done');
});

module.exports = {
    run
}