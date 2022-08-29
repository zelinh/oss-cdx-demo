const json5 = require('json5');
const fs = require('fs');
const path = require('path');

const configRoot = path.join(__dirname, '../config');
const configStore = {};

const isObject = value => value && typeof value === "object" && !Array.isArray(value);

const deepFreeze = obj => {
    const propNames = Object.getOwnPropertyNames(obj);
    for (const name of propNames) {
        const value = obj[name];
        if (value && typeof value === "object") deepFreeze(value);
    }

    return Object.freeze(obj);
};

const deepMerge = (target, source) => {
    if (isObject(target) && isObject(source)) {
        for (const key in source) {
            if (isObject(source[key])) {
                if (!target[key]) Object.assign(target, { [key]: {} });
                deepMerge(target[key], source[key]);
            } else {
                Object.assign(target, { [key]: source[key] });
            }
        }
    }

    return target;
};

const deepExpand = obj => {
    const propNames = Object.getOwnPropertyNames(obj);
    for (const name of propNames) {
        const keys = name?.split?.('.')?.filter?.(el => el);
        const value = isObject(obj[name]) ? deepExpand(obj[name]) : obj[name];
        if (keys?.length > 1) {
            delete obj[name];
            const o = {};
            const lastKey = keys.pop();
            let node = o;
            for (const key of keys) {
                Object.assign(node, { [key]: {} });
                node = node[key];
            }
            Object.assign(node, { [lastKey]: value });
            deepMerge(obj, o);
        } else {
            Object.assign(obj, { [name]: value });
        }
    }

    return obj;
}
/**
 *
 * @param prop
 * @returns {Object.<string, (Object|string|number)>}
 */
const getConfig = prop => {
    const keys = (Array.isArray(prop) ? prop : prop?.split?.('.'))?.filter?.(el => el);
    let config = configStore;
    for (let i = 0, len = keys.length; i < len; i++) {
        config = config[keys[i]];
        if (config === undefined) break;
    }

    return config;
}

const processDir = dir => {
    const config = {};
    const names = fs.readdirSync(dir);
    for (let i = 0, len = names.length; i < len; i++) {
        const resolvedPath = path.join(dir, names[i]);
        const baseName = path.basename(names[i]).replace(/\.json5?$/i, '');
        const stats = fs.statSync(resolvedPath);
        if (stats.isDirectory()) {
            config[baseName] = processDir(resolvedPath);
        } else if (/\.json5?$/i.test(names[i])) {
            const content = fs.readFileSync(resolvedPath, 'utf-8')?.replace?.(/^\uFEFF/, '');
            config[baseName] = json5.parse(content);
        }
    }

    return config;
}

Object.assign(configStore, deepExpand(processDir(configRoot)));
// ToDo: Add parsing of argv and env

deepFreeze(configStore);

module.exports = {
    get: getConfig
};