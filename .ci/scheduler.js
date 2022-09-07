const util = require('util');
const exec = util.promisify(require('child_process').exec);
const config = require('../lib/config.js');
const Git = require("../lib/git.js");
const { sleep } = require("../lib/sleep.js");

const buildConfig = config.get('ci.codebuild');
const PARALLEL_COUNT = buildConfig.parallelCount || 20;

const triggerSBOMGeneration = async project => {
    if (project.disabled) return;

    try {
        const { stdout, stderr } = await exec(`echo '${JSON.stringify({
            projectName: buildConfig.worker,
            environmentVariablesOverride: [
                {
                    name: 'CDX_PROJECT',
                    value: JSON.stringify([project]),
                    type: "PLAINTEXT"
                },
                {
                    name: 'CDX_JOB',
                    value: "SBOM",
                    type: "PLAINTEXT"
                }
            ],
        }).replace(/'/g, "\'")}' | xargs -0 aws codebuild start-build --cli-input-json`, {
            maxBuffer: 10 * 1024 * 1024
        });
        if (stderr) {
            console.error('Error on', project, 'with', stderr);
        }
        const { build } = JSON.parse(stdout.toString());
        return build.id;
    } catch (ex) {
        if (ex.toString().indexOf('AccountLimitExceededException') !== -1) {
            console.log('Holding...');
            await sleep(30000);
            return triggerSBOMGeneration(project);
        }
        console.error('Exception on', project, 'with', ex);
    }
};

const triggerAdvisoriesTask = async () => {
    try {
        const { stdout, stderr } = await exec(`echo '${JSON.stringify({
            projectName: buildConfig.worker,
            environmentVariablesOverride: [
                {
                    name: 'CDX_JOB',
                    value: "ADVS",
                    type: "PLAINTEXT"
                }
            ],
        }).replace(/'/g, "\'")}' | xargs -0 aws codebuild start-build --cli-input-json`, {
            maxBuffer: 10 * 1024 * 1024
        });
        if (stderr) {
            console.error('Error on ADVS with', stderr);
        }
        const { build } = JSON.parse(stdout.toString());
        return build.id;
    } catch (ex) {
        if (ex.toString().indexOf('AccountLimitExceededException') !== -1) {
            console.log('Holding...');
            await sleep(30000);
            return triggerAdvisoriesTask();
        }
        console.error('Exception on ADVS with', ex);
    }
};

const triggerScan = async () => {
    try {
        const { stdout, stderr } = await exec(`echo '${JSON.stringify({
            projectName: buildConfig.worker,
            environmentVariablesOverride: [
                {
                    name: 'CDX_JOB',
                    value: "VULS",
                    type: "PLAINTEXT"
                }
            ],
        }).replace(/'/g, "\'")}' | xargs -0 aws codebuild start-build --cli-input-json`, {
            maxBuffer: 10 * 1024 * 1024
        });
        if (stderr) {
            console.error('Error on VULS with', stderr);
        }
        const { build } = JSON.parse(stdout.toString());
        return build.id;
    } catch (ex) {
        if (ex.toString().indexOf('AccountLimitExceededException') !== -1) {
            console.log('Holding...');
            await sleep(30000);
            return triggerAdvisoriesTask();
        }
        console.error('Exception on VULS with', ex);
    }
};

const triggerWeeklySummary = async () => {
    try {
        const { stdout, stderr } = await exec(`echo '${JSON.stringify({
            projectName: buildConfig.worker,
            environmentVariablesOverride: [
                {
                    name: 'CDX_JOB',
                    value: "SUMM",
                    type: "PLAINTEXT"
                }
            ],
        }).replace(/'/g, "\'")}' | xargs -0 aws codebuild start-build --cli-input-json`, {
            maxBuffer: 10 * 1024 * 1024
        });
        if (stderr) {
            console.error('Error on SUMM with', stderr);
        }
        const { build } = JSON.parse(stdout.toString());
        return build.id;
    } catch (ex) {
        if (ex.toString().indexOf('AccountLimitExceededException') !== -1) {
            console.log('Holding...');
            await sleep(30000);
            return triggerAdvisoriesTask();
        }
        console.error('Exception on SUMM with', ex);
    }
};

const getCompletedBuilds = async builds => {
    const { stdout } = await exec(`aws codebuild batch-get-builds --ids ${builds.join(' ')}`);
    return JSON.parse(stdout.toString()).builds.reduce((arr, build) => {
        console.log(`${build.id}: ${build.currentPhase}`);
        if (build.currentPhase === 'COMPLETED') arr.push(build.id);
        return arr;
    }, []);
}

const waitForBuild = async (label, builds) => {
    let errors = 0;
    while (builds.length > 0) {
        console.log(`Waiting for ${label} tasks to complete...`);
        await sleep(60000);
        const completedBuilds = await getCompletedBuilds(builds);
        if (Array.isArray(completedBuilds)) {
            completedBuilds.forEach(buildId => builds.splice(builds.indexOf(buildId), 1));
        } else {
            console.error(`${++errors}/3: Failed to check status of ${label} tasks`);
            if (errors >= 3) process.exit(1);
        }
    }
};

const generateSBOMs = async (specificProject) => {
    console.log('SBOM Started ...');

    const projects = [];
    const builds = [];

    let errors = 0;

    for await (const project of config.get('projects')) {
        if (project.disabled) continue;

        if (specificProject && specificProject !== project.name) continue;

        if (project.parallel === false) {
            const forcedBranches = project['additional-branches']
                    ? Array.isArray(project['additional-branches'])
                        ? project['additional-branches']
                        : [project['additional-branches']]
                    : [],
                tags = (project.tag ? [await Git.getTag(project.repo, project.tag, project.hash)] : await Git.getInfo(project.repo, forcedBranches))
                    .filter(tag => tag.tag),
                ignoredTags = [];

            if (Array.isArray(project['ignored-tags'])) ignoredTags.push(...project['ignored-tags']);
            else if (project['ignored-tags']) ignoredTags.push(project['ignored-tags']);

            const ignoreAll = ignoredTags.includes('*');

            console.log(`Found ${tags.length} tag${tags.length === 1 ? '' : 's'} for ${project.name}`);
            for (const tag of tags) {
                if (ignoredTags.includes(tag.tag) || /-(rc|alpha|beta)\d*$/.test(tag.tag)) {
                    console.log(`[${project.name}]\tSkipping ${tag.tag}`);
                    continue;
                }

                if (ignoreAll && !forcedBranches.includes(tag.tag)) {
                    console.log(`[${project.name}]\tSkipping ${tag.tag}`);
                    continue;
                }

                projects.push({ ...project, ...tag });
            }
        } else {
            projects.push(project);
        }
    }

    let cnt = 0;
    for (const project of projects) {
        const buildId = await triggerSBOMGeneration(project);
        if (buildId) {
            builds.push(buildId);
            console.log(`Started (${builds.length}: ${++cnt}/${projects.length}) ${buildId}`);
        }

        errors = 0;
        while (builds.length >= PARALLEL_COUNT) {
            console.log('Waiting...');
            await sleep(60000);
            const completedBuilds = await getCompletedBuilds(builds);
            if (Array.isArray(completedBuilds)) {
                completedBuilds.forEach(buildId => builds.splice(builds.indexOf(buildId), 1));
            } else {
                console.error(`${++errors}/3: Failed to check task status`);
                if (errors >= 3) process.exit(1);
            }
        }
    }

    await waitForBuild('SBOM', builds);
    console.log('SBOM Done.');
};

const run = async (specificProject) => {
    await generateSBOMs(specificProject);

    console.log('ADVS Started ...');
    await waitForBuild('ADVS', [await triggerAdvisoriesTask()]);
    console.log('ADVS Done.');

    console.log('VULS Started ...');
    await waitForBuild('VULS', [await triggerScan()]);
    console.log('VULS Done.');

    const date = new Date();
    if (0 && date.getDay() === 3) {
        console.log('SUMM Started ...');
        await waitForBuild('SUMM', [await triggerWeeklySummary()]);
        console.log('SUMM Done.');
    }
};

const args = process.argv.slice(-1);

if (args.length > 0) {
    let project_;
    for (const project of config.get('projects')) {
        if (project.name === args[0]) {
            project_ = project;
            break;
        }
    }

    if (project_) {
        console.log(`Running for ${project_.name}...`);
        run(project_.name).catch(console.error);
    } else {
        run().catch(console.error);
    }
}