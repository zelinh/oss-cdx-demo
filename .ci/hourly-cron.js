const CodeBuild = require('./lib/codebuild');
const { sendLatestNews } = require("../lib/summary");
const { sleep } = require("../lib/sleep");


const run = async () => {
    await CodeBuild.run.advisories();
    await CodeBuild.run.scan();

    console.log('Waiting a bit...');
    await sleep(60000);

    await sendLatestNews();
};

run().catch(console.error);