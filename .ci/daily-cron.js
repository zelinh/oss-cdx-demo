const config = require('../lib/config.js');
const CodeBuild = require('./lib/codebuild');
const { sendLatestNews } = require("../lib/summary");


const run = async (specificProject) => {
    await CodeBuild.run.sboms(specificProject);
    await CodeBuild.run.advisories();
    await CodeBuild.run.scan();
    await CodeBuild.run.weeklySummary();

    await sendLatestNews();
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