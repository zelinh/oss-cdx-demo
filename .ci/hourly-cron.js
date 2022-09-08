const CodeBuild = require('./lib/codebuild');
const { sendLatestNews } = require("../lib/summary");


const run = async () => {
    await CodeBuild.run.advisories();
    await CodeBuild.run.scan();

    await sendLatestNews();
};

run().catch(console.error);