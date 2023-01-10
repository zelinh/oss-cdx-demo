const util = require("../util");
const { normalize } = require("../../normalizer");
module.exports = {
    parse: json => {
        if (!json?.identifier) throw new Error(`MISSING_ID`);

        const res = {
            source: ['gitlab'],
        };

        if (!/^[A-Z]+-/.test(json.identifier)) json.identifier = `GLSA-${json.identifier}`;
        json.identifiers = json.identifiers.map(id => /^[A-Z]+-/.test(id) ? id : `GLSA-${id}`);

        util.addIdentifiers(res, json.identifier, json.identifiers);

        const title = json.title?.trim?.();
        if (title) res.title = title;

        const description = json.description?.replace?.(/\s*[\r\n]+\s*/g, ' ').trim();
        if (description) res.description = description;

        if (json.package_slug) {
            const product = {
                source: 'gitlab'
            };
            const [productType, ...tokens] = json.package_slug.split('/');
            product.ecosystem = normalize.ecosystem(productType);
            product.name = tokens.join('/');

            product.version = normalize.version(json.affected_range) || '*';

            res.products = [product];
        }

        if (json.pubdate && json.pubdate !== '1970-01-01') {
            try {
                res.timestamp = {
                    publish: (new Date(json.pubdate)).toISOString()
                };
            } catch (e) {
                // Do nothing
            }
        }

        return res;
    }
}