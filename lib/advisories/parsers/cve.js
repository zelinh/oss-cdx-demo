const util = require("../util");
const { normalize } = require("../../normalizer");
const badVendors = ['n/a', 'HackerOne', 'Snyk', '[UNKNOWN]'];
const badProducts = ['n/a'];
const badVersions = ['n/a', 'unknown', 'N/A', 'None'];

module.exports = {
    parse: json => {
        if (!json?.CVE_data_meta) throw new Error(`MISSING_ID`);

        const meta = {
            severity: normalize.severity(json.impact?.cvss?.baseSeverity),
            source: 'cve'
        };

        util.addIdentifiers(meta, json.CVE_data_meta.ID);

        const title = json.CVE_data_meta.TITLE?.trim?.();
        if (title) meta.title = title;

        if (Array.isArray(json.description?.description_data)) {
            for (const dd of json.description?.description_data) {
                if (dd.lang === 'en' || dd.lang === 'eng') {
                    const descriptionData = dd.value?.trim?.();
                    if (descriptionData) {
                        meta.description = descriptionData;
                        break;
                    }
                }
            }
        }

        const products = [];
        const productsMap = [];

        json.affects?.vendor?.vendor_data?.forEach?.(vd => {
            const vendorName = badVendors.includes(vd.vendor_name) ? undefined : vd.vendor_name;

            vd.product?.product_data?.forEach?.(pd => {
                if (badProducts.includes(pd.product_name)) return;

                const productName = pd.product_name?.trim?.().replace(/:+/g, '/');
                const productVersionNames = new Set();

                const versions = new Set();
                let prevVersion = {};

                pd.version?.version_data?.forEach?.(vd => {
                    let version = vd.version_value?.trim?.();
                    if (!version || badVersions.includes(version)) return;

                    const productVersionName = vd.version_name?.trim?.().replace(/:+/g, '/');
                    if (productVersionName) {
                        if (/^\w+$/.test(version) && /^(\d+\.+)*\d+$/.test(productVersionName)) {
                            version = productVersionName;
                        } else {
                            version = version
                                .replace(vd.version_name + ' ', '')
                                .replace(vd.version_name + ': ', '');

                            if (productVersionName.toLowerCase() !== 'all' && !/^([><=]+\s*)?(\d+\.+)*\d+$/.test(productVersionName)) {
                                productVersionNames.add(productVersionName);
                            }
                        }
                    }

                    version = version
                        .replace(pd.product_name + ' ', '')
                        .replace(pd.product_name + ': ', '');

                    version = normalize.version(version);

                    if (vd.version_affected && version !== '*')
                        version = `${vd.version_affected}${version}`;
                    /*
                    if (!/^[<>]=?\s/.test(version) && !/^\d+(\.|$)/.test(version) && version !== '*') {
                        console.log(json.CVE_data_meta.ID, version, '/', vd.version_value);
                    }
                     */

                    const currentVersion = {
                        name: productVersionName,
                    }

                    if (version && !versions.has(version) && version !== productName) {
                        if (version.split(/[<>]/).length === 2) currentVersion.opening = version[0];
                        if (currentVersion.name === prevVersion.name && currentVersion.opening === '<' && prevVersion.opening === '>') {
                            const prev = versions.pop();
                            versions.add(prev + ' ' + version);
                        } else
                            versions.add(version);
                    }

                    prevVersion = currentVersion;
                });

                const res = {
                    name: productVersionNames.size === 1 ? productVersionNames.values().next().value : productName,
                    source: ['cve']
                };
                if (versions.size !== 0) res.version = Array.from(versions).join(' || ');
                if (vendorName) {
                    res.vendor = vendorName;
                    res.package = res.name;
                    res.name = vendorName + '/' + res.name;
                }

                if (!productsMap.includes(`${res.vendor}//${res.name}//${res.version}`)) {
                    products.push(res);
                    productsMap.push(`${res.vendor}//${res.name}//${res.version}`);
                }
            });
        });

        if (products.length) meta.products = products;

        return meta;
    }
}
