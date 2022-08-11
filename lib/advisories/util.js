const fs = require("fs-extra");
const path = require("path");
const os = require("os");
const CACHE_ROOT = path.join(os.tmpdir(), 'oss-cve-cache');

const upsert = (node, key, value) => {
    if (node[key]) {
        let changed = false;
        const nodeKeys = Array.isArray(node[key]) ? node[key] : [node[key]];
        const _values = Array.isArray(value) ? value : [value];

        _values.forEach(_value => {
            if (value !== undefined && value !== null && !nodeKeys.includes(_value)) {
                nodeKeys.push(_value);
                changed = true;
            }
        });

        if (changed) node[key] = nodeKeys;
    } else if (Array.isArray(value)) {
        node[key] = Array.from(new Set(value)).filter(v => v !== undefined && v !== null);
    } else if (value !== undefined && value !== null) {
        node[key] = value;
    }
};

const addIdentifiers = (node, id, aliases) => {
    if (!node) return;
    if (!node.aliases) node.aliases = [];

    if (id && !node.aliases.includes(id)) node.aliases.push(id);
    if (node.id && !node.aliases.includes(node.id)) node.aliases.push(node.id);

    if (aliases) {
        const _aliases = Array.isArray(aliases) ? aliases : [aliases];
        _aliases.forEach(alias => {
            if (!node.aliases.includes(alias)) node.aliases.push(alias);
        });
    }

    // If node has a CVE ID, terminate
    if (node.id && /^CVE-/.test(node.id)) return;

    // Find a CVE ID and terminate
    if (node.aliases.some(id => {
        if (/^CVE-/.test(id)) {
            node.id = id;
            return true;
        }
    })) return;

    // When no suitable ID found, just take first alias
    if (!node.id && node.aliases.length) node.id = node.aliases[0];
};

const severityLevels = [
    'UNDEFINED',
    'LOW',
    'MEDIUM',
    'HIGH',
    'CRITICAL',
];

const getHighestSeverity = severities => {
    if (!Array.isArray(severities) || severities.length === 0) return severities;
    if (severities.length === 1) return severities[0];

    const levels = severities.map(sev => severityLevels.indexOf(sev));
    return severityLevels[Math.max(...levels)];
};

const merge = (node, leaf) => {
    addIdentifiers(node, leaf.id, leaf.aliases);

    ['aliases', 'severity', 'source', 'title', 'description'].forEach(key => {
        if (leaf[key]) upsert(node, key, leaf[key])
    });

    if (node.severity) node.severity = getHighestSeverity(node.severity);

    if (Array.isArray(leaf.products)) {
        if (Array.isArray(node.products)) {
            const productMap = {};
            node.products.forEach(product => {
                productMap[`${product.vendor}//${product.name}//${product.version}`] = product;
            });

            leaf.products.forEach(product => {
                const key = `${product.vendor}//${product.name}//${product.version}`;
                // If we know about this product, just update the source and ecosystem
                if (productMap[key]) {
                    upsert(productMap[key], 'source', product.source);
                    upsert(productMap[key], 'ecosystem', product.ecosystem);
                } else {
                    productMap[key] = product;
                }
            });

            const badProductMapKeys = {
                startVersioned: [],
                noType: []
            };
            const productMapKeys = Object.keys(productMap);
            const productMapSize = productMapKeys.length;
            productMapKeys.forEach(key => {
                if (productMap[key].version === '*') badProductMapKeys.startVersioned.push(key);
                else if (!productMap[key].ecosystem) badProductMapKeys.noType.push(key);
            });

            // Remove '*' versions, if there are other products listed
            const starVersionedSize = badProductMapKeys.startVersioned.length;
            if (productMapSize > starVersionedSize) {
                badProductMapKeys.startVersioned.forEach(key => {
                    delete productMap[key];
                });
            }

            // Remove those with no types when there are others available
            if (productMapSize - starVersionedSize > badProductMapKeys.noType.length) {
                badProductMapKeys.noType.forEach(key => {
                    delete productMap[key];
                });
            }

            node.products = Object.values(productMap);
        } else {
            node.products = [...leaf.products];
        }
    }

    if (leaf.timestamp?.publish) {
        if (!node.timestamp) node.timestamp = {};
        if (!node.timestamp.publish || node.timestamp.publish > leaf.timestamp.publish) {
            node.timestamp.publish = leaf.timestamp.publish;
        }
    }
};

const isWithdrawn = rec => {
    if (!rec.description) return;
    const descriptions = Array.isArray(rec.description) ? rec.description : [rec.description];
    return descriptions.some(description => /(^\s*\*\*\s*(REJECT|Withdrawn):?\s*\*\*|withdrawn by its (CNA|its requester|the CVE program)|(^|\r|\n)\s*#\s*Withdrawn|Withdrawn, accidental duplicate publish|\*\*\s*Withdrawn:?\s*\*\*\s*Duplicate of|Withdrawn:\s*Duplicate of|^\s*WITHDRAWN\s*$)/i.test(description));
};

module.exports = {
    traverse: async (dir, func, selectPattern, excludes) => {
        const _excludes = Array.isArray(excludes) ? excludes : [excludes];
        const traverse = async loc => {
            const files = await fs.readdir(loc);
            for await (const _file of files) {
                if (_excludes.includes(_file)) continue;

                const file = path.join(loc, _file);
                const stat = await fs.stat(file);
                if (stat.isDirectory()) await traverse(file);
                else if (!selectPattern || selectPattern.test?.(_file)) {
                    await func(file);
                }
            }
        };

        return traverse(dir);
    },

    cache: {
        init: async key => {
            const dir = path.join(CACHE_ROOT, key);
            // Better performance with Node 14.4.0
            await fs.remove(dir);
            await fs.emptyDir(dir);

            return dir;
        },

        save: async (key, data) => {
            const _data = Array.isArray(data) ? data : [data];
            for await (const _d of _data) {
                if (!_d?.id) throw 'Missing ID';

                const dest = path.join(CACHE_ROOT, key, `${_d.id}.json`);

                try {
                    await fs.access(dest, fs.constants.R_OK);
                    merge(_d, await fs.readJSON(dest));

                } catch (e) {
                    // File doesn't exist
                }

                await fs.outputJSON(dest, _d);
            }
        },

        finalize: async (cacheDirs, func) => {
            let list = [...cacheDirs];
            if (list.length === 0) return;

            const now = new Date();

            const idCollection = new Map();
            const idPointers = {};

            let cnt = 0;
            for await (const loc of list) {
                console.log(`Catalogue: ${++cnt}/${list.length}`);

                const files = await fs.readdir(loc);
                for await (let file of files) {
                    const thisFile = path.join(loc, file);
                    const rec = await fs.readJSON(thisFile);

                    let id_ = false;
                    for (const alias of rec.aliases) {
                        if (idPointers[alias]) {
                            id_ = idPointers[alias];
                            break;
                        }
                    }

                    if (!id_) id_ = rec.id;

                    for (const alias of rec.aliases) {
                        idPointers[alias] = id_;
                    }

                    if (idCollection.has(id_)) {
                        idCollection.get(id_).add(thisFile);
                    } else {
                        idCollection.set(id_, new Set([thisFile]));
                    }
                }
            }

            cnt = 0;
            size = idCollection.size;
            for await (const [key, files] of idCollection) {
                if (++cnt % 1000 === 0) console.log(`${cnt}/${size}...`);

                const [thisFile, ...otherFiles] = Array.from(files);
                const rec = await fs.readJSON(thisFile);
                await fs.remove(thisFile);

                for await (let otherFile of otherFiles) {
                    if (await fs.pathExists(otherFile)) {
                        merge(rec, await fs.readJSON(otherFile));
                        await fs.remove(otherFile);
                    }
                }

                if (isWithdrawn(rec)) rec.withdrawn = true;

                upsert(rec, 'ecosystem', rec.products?.map?.(product => product.ecosystem));

                if (!rec.timestamp) rec.timestamp = {};
                rec.timestamp.scan = now;

                await func(rec);
            }

            await func(null, true);
        },
    },

    addIdentifiers,
    merge,
    getHighestSeverity
}