const { parentPort } = require('worker_threads');

const run = async source => {
    console.log(`[${source}]\tWorking on advisory...`);

    try {
        const sourceHandler = require(`./sources/${source}`);
        return await sourceHandler.fetch();
    } catch (ex) {
        console.error(ex);
    }
};

parentPort.on('message', async source => {
    const artifactsDir = await run(source);
    if (artifactsDir) parentPort.postMessage({ artifactsDir });
    parentPort.postMessage('done');
});