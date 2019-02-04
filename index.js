const Boom = require('boom');
const LruCache = require('lru-cache');
const AUTH_CACHE_LRU = new LruCache(100);

let globalAbilities;
let defaultAbilities;

const AUTH_CACHE = {
    get: (key) => AUTH_CACHE_LRU.get(key),
    has: (key) => AUTH_CACHE_LRU.has(key),
    set: (key, data) => AUTH_CACHE_LRU.set(key, data),
    del: (key) => AUTH_CACHE_LRU.del(key),
    keys: () => AUTH_CACHE_LRU.keys(),
};

async function getUserAbilities(user) {
    return (globalAbilities && typeof globalAbilities[user.role] === 'function') ? await globalAbilities[user.role](user) : defaultAbilities;
}

function mkAuthentication({abilities, parseToken, getCurrentUser}) {
    if (globalAbilities !== undefined) throw 'Only one instance accepted';
    globalAbilities = abilities;
    defaultAbilities = (globalAbilities && typeof globalAbilities.default === 'function') ? globalAbilities.default() : null;
    return async (req, res, next) => {
        try {
            let payload = await parseToken(req.headers.authorization);
            let user = {};
            let ability = {};
            if (payload.id && AUTH_CACHE.has(payload.id)) {
                let cached = AUTH_CACHE.get(payload.id);
                user = cached.user;
                ability = cached.ability;
            } else if (payload.id) {
                user = await getCurrentUser(payload);
                ability = await getUserAbilities(user);
                AUTH_CACHE.set(payload.id, {user, ability});
            }
            req.user = user;
            req.ability = ability;
            req.authenticated = true;
        } catch (e) {
            req.ability = defaultAbilities;
            req.authenticated = false;
        }
        next();
    }
}

function mustBeAuthenticated() {
    return (req, res, next) => {
        req.authenticated ? next() : next(Boom.unauthorized());
    }
}

module.exports = {authentication: mkAuthentication, mustBeAuthenticated, AUTH_CACHE, getUserAbilities};