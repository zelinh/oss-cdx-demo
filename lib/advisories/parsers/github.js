const util = require("../util");
const { normalize } = require("../../normalizer");

module.exports = {
    parse: json => {
        if (!json?.id) throw new Error(`MISSING_ID`);

        const res = {
            source: 'github',
            severity: normalize.severity(json.database_specific?.severity)
        };

        util.addIdentifiers(res, json.id, json.aliases);

        const summary = json.summary?.trim?.();
        if (summary) res.title = summary;

        if (json.details) res.description = json.details;

        if (Array.isArray(json.affected)) {
            const products = [];
            json.affected.forEach(item => {
                if (!item.package) throw 'NO_PACKAGE';

                const product = {
                    name: item.package.name?.replace(/:+/g, '/'),
                    source: ['github']
                };

                if (item.package.ecosystem) product.ecosystem = normalize.ecosystem(item.package.ecosystem);

                const versions = [];
                let foundIntroducedZero = false;
                if (Array.isArray(item.ranges)) {
                    item.ranges.forEach(range => {
                        //if (!Array.isArray(range.events) || range.events.length === 0) throw "MISSING_RANGES";
                        //if (range.events.length > 2) throw "TOO_MANY_RANGES";

                        let res = [];
                        range.events.forEach(({introduced, fixed, ...rest}) => {
                            if (introduced) {
                                if (introduced === '0') foundIntroducedZero = true;
                                else res.push(`>=${introduced}`);
                            }
                            if (fixed) res.push(`<${fixed}`);

                            //if (Object.keys(rest).length !== 0) throw `UNHANDLED_EVENT: ${Object.keys(rest).join(', ')}`;
                        });
                        if (res.length) versions.push(res.join(' '));
                    });
                }
                if (Array.isArray(item.versions)) versions.push(...item.versions);
                if (
                    versions.length === 0 &&
                    item.database_specific?.last_known_affected_version_range
                ) versions.push(item.database_specific?.last_known_affected_version_range);
                /*
                if (item.database_specific) {
                    const {last_known_affected_version_range, ... rest} = item.database_specific;
                    if (Object.keys(rest).length) throw `UNHANDLED_SPECIFICS: ${Object.keys(rest).join(', ')}`;
                }
                 */

                if (!versions.length) {
                    if (foundIntroducedZero) versions.push('*');
                    else throw 'NO_VERSIONS';
                }
                product.version = versions.join(' || ');

                products.push(product);
            });

            if (products.length) res.products = products;
        }

        if (json.published) {
            try {
                res.timestamp = {
                    publish: (new Date(json.published)).toISOString()
                };
            } catch (e) {
                // Do nothing
            }
        }

        return res;
    }
}