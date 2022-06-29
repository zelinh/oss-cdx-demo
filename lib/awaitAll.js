const awaitAll = async awaitCalls => {
    const results = [];
    for (const awaitCall of awaitCalls) {
        results.push(await awaitCall);
    }

    return results;
}

module.exports = {
    awaitAll
}