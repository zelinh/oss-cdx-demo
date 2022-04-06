const Git = require('../git');
const WorkerPool = require('../worker_pool');
const os = require('os');
const config = require('../config');
const path = require("path");
const numThreads = os.cpus().length;

process.env.FETCH_LICENSE = 'true';

const run = async () => {
    console.log('SBOM task started');
    const tasks = [];
    const projects = config.get('projects');
    for await (const project of projects) {
        if (project.disabled) continue;

        console.log('');
        console.log(`[${project.name}]\tReading tags from ${project.repo}`);

        const forcedBranches = project['additional-branches']
            ? Array.isArray(project['additional-branches'])
                ? project['additional-branches']
                : [project['additional-branches']]
            : [];
        const tags = (project.tag ? [await Git.getTag(project.repo, project.tag, project.hash)] : await Git.getInfo(project.repo, forcedBranches))
            .filter(tag => tag.tag);

        const ignoredTags = [];
        if (Array.isArray(project['ignored-tags'])) ignoredTags.push(...project['ignored-tags']);
        else if (project['ignored-tags']) ignoredTags.push(project['ignored-tags']);

        console.log(`Found ${tags.length} tag${tags.length === 1 ? '' : 's'} for ${project.name}`);
        for await (const tag of tags) {
            if (ignoredTags.includes(tag.tag) || /-(rc|alpha|beta)\d*$/.test(tag.tag)) {
                console.log(`[${project.name}]\tSkipping ${tag.tag}`);
                continue;
            }
            tasks.push({ ...project, ...tag });
        }
    }

    console.log('');
    const numTasks = tasks.length;
    if (numTasks === 0) return;

    return new Promise((resolve, reject) => {
        let numPending = numTasks;
        let hasFailure = false;
        const pool = new WorkerPool(path.join(__dirname, 'worker.js'), Math.ceil(numThreads / 2));
        for (let i = 0; i < numTasks; i++) {
            // Add a delay between invocations to avoid install conflicts
            setTimeout(() => {
                pool.runTask(tasks[i], (err, result) => {
                    if (err) {
                        console.error(`${tasks[i].name}@${tasks[i].tag} failed:`, err);
                        if (!hasFailure) hasFailure = err;
                    }
                    if (result && result !== 'done') console.log(result);
                    if (--numPending <= 0) {
                        pool.close();

                        if (hasFailure) {
                            console.log('SBOM task unsuccessful');
                            reject(hasFailure);
                        } else {
                            console.log('SBOM task completed');
                            resolve();
                        }
                    }
                }, null, projects.parallel);
            }, 5000 * i);
        }
    });
};

module.exports = {
    run
}