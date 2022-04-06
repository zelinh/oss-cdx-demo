const cve = require("./cve");
const { normalize } = require("../../normalizer");

// For now, ignore operators
const parseCPEs = node => {
    const els = [];
    if (Array.isArray(node.children) && node.children.length) {
        els.push(...node.children.map(parseCPEs));
    }
    if (Array.isArray(node.cpe_match) && node.cpe_match.length) {
        els.push(...node.cpe_match.map(cpe => {
            if (!cpe.vulnerable) throw 'non-vulnerable';
            return cpe.cpe23Uri;
        }));
    }

    return els;
}

module.exports = {
    parse: json => {
        if (json?.configurations?.CVE_data_version !== '4.0') throw new Error(`BAD_VERSION`);

        const cveData = json.cve ? cve.parse(json.cve) : {};
        cveData.products?.forEach?.(product => product.source = ['nvd']);
        const res = {
            ...cveData,
            severity: normalize.severity(json.impact?.baseMetricV3?.cvssV3?.baseSeverity || json.impact?.baseMetricV2?.severity),
            source: 'nvd'
        };

        if (json.configurations.nodes) {
            const cpe23Uris = parseCPEs(json.configurations.nodes);
            if (cpe23Uris.length) res.CPEs = cpe23Uris;
        }

        if (json.publishedDate) {
            try {
                res.timestamp = {
                    publish: (new Date(json.publishedDate)).toISOString()
                };
            } catch (e) {
                // Do nothing
            }
        }

        return res;
    }
}