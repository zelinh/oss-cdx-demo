const cve = require("./cve");
const util = require("../util");
const nvd = require("./nvd");
const gitlab = require("./gitlab");
const { normalize } = require("../../normalizer");

module.exports = {
    parse: json => {
        const res = {
            id: json.GSD?.id,
            source: 'gsd',
            aliases: []
        };

        if (json.GSD) {
            util.addIdentifiers(res, json.GSD.id, json.GSD.alias);

            if (json.GSD.product_name && json.GSD.product_version) {
                const gsdProduct = {
                    name: json.GSD.product_name,
                    version: normalize.version(json.GSD.product_version)
                };
                if (json.GSD.vendor_name) {
                    gsdProduct.vendor = json.GSD.vendor_name;
                    gsdProduct.package = gsdProduct.name;
                    gsdProduct.name = gsdProduct.vendor + '/' + gsdProduct.name;
                }

                res.products = [gsdProduct];
            }

            const gsdDescription = json.GSD.description?.trim?.()?.replace?.(/\s*[\r\n]+\s*/g, ' ');
            if (gsdDescription) res.description = gsdDescription;
        }

        if (json.gsd?.osvSchema) {
            util.merge(res, {
                id: json.gsd.osvSchema.id,
                source: 'gsd',
                title: json.gsd.osvSchema.summary,
                description: json.gsd.osvSchema.details?.replace?.(/\s*[\r\n]+\s*/g, ' '),
            });

            if (json.gsd.osvSchema.published) {
                try {
                    res.timestamp = {
                        publish: (new Date(json.gsd.osvSchema.published)).toISOString()
                    };
                } catch (e) {
                    // Do nothing
                }
            }
        }

        if (json.OSV) {
            util.merge(res, {
                id: json.OSV.id,
                source: 'osv',
                title: json.OSV.summary,
                description: json.OSV.details?.replace?.(/\s*[\r\n]+\s*/g, ' ')
            });
        }

        if (json.namespaces) {
            Object.keys(json.namespaces).forEach(key => {
                switch (key) {
                    case 'cve.org':
                        const cveData = cve.parse(json.namespaces[key]);
                        cveData?.products?.forEach?.(product => product.source = ['gsd']);
                        util.merge(res, cveData);
                        break;

                    case 'nvd.nist.gov':
                        const nvdData = nvd.parse(json.namespaces[key]);
                        nvdData?.products?.forEach?.(product => product.source = ['gsd']);
                        util.merge(res, nvdData);
                        break;

                    case 'gitlab.com':
                        if (json.namespaces[key].advisories) {
                            const advisories = Array.isArray(json.namespaces[key].advisories) ? json.namespaces[key].advisories : [json.namespaces[key].advisories];
                            advisories.forEach(advisory => {
                                const glData = gitlab.parse(advisory);
                                glData?.products?.forEach?.(product => product.source = ['gsd']);
                                util.merge(res, glData);
                            });
                        }
                        break;

                    case 'cisa.gov':
                        // Not useful
                        break;

                    default:
                        //console.log(`${key} is not handled in GSD: ${res.id}`);

                }
            });
        }

        if (!res.id) throw new Error(`MISSING_ID`);

        return res;
    }
}
