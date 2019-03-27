import MongoClient, {ObjectId} from 'mongodb';
import './utils';

const ACL_MGT_PERMISSION = 'user.editPermissions';
const APPLICATIONS = [
    "customerServicePortal",
    "programManagement",
    "reporting",
    "userAdmin",
    "documentReview"
];

const processPermissionImplies = (permission, allPermissions, toReturn) => {
    if (!permission || Array.isEmpty(permission.implies))
        return;

    permission.implies.forEach(impliedPermName => {
        if (toReturn.find(existingPerm => existingPerm.name === impliedPermName))
            return;

        const foundPermDefn = allPermissions.find(foundPerm => foundPerm.name === impliedPermName);
        if (!foundPermDefn)
            return;

        toReturn.push({name: foundPermDefn.name, scopes: []});

        processPermissionsImplies(foundPermDefn, allPermissions, toReturn);
    });
};

const processPermissionsImplies = (currentPerms, allPermsPromise) => {
    return allPermsPromise.then(allPerms => {
        const toReturn = [ ...currentPerms ];
        toReturn.forEach(perm => {
            const foundPerm = allPerms.find({name: perm.name});
            processPermissionImplies(foundPerm, allPerms, toReturn);
        });
        return toReturn;
    });
};
const combinePermissions = (permissionsArrays) => {
    const perms = [];
    const permNames = [];

    permissionsArrays.forEach(permsArr => {
        permsArr.forEach(p => {
            if (permNames.indexOf(p.name) !== -1) {
                if (Array.isEmpty(p.scopes))
                    return;

                const p2 = perms.find(pt => pt.name === p.name);

                if (Array.isEmpty(p2.scopes)) {
                    p2.scopes = p.scopes;
                    return;
                }

                p2.scopes = [ ...new Set(p.scopes.concat(p2.scopes)) ];

                return;
            }

            permNames.push(p.name);
            perms.push(p);
        });
    });

    return perms;
};

const processRevokes = (superset, revokes) => {
    if (Array.isEmpty(superset))
        return [];
    if (Array.isEmpty(revokes))
        return superset;

    let results = [ ...superset ];

    revokes.forEach(p => {
        if (Array.isEmpty(p.scopes)) {
            results = results.filter(p2 => p2.name !== p.name);
            return;
        }
        const gp = results.find(p2 => p.name === p.name);
        if (!gp)
            return;
        if (Array.isEmpty(gp.scopes)) {
            results = results.filter(p2 => p2.name !== p.name);
            return;
        }

        gp.scopes = gp.scopes.filter(s => p.scopes.indexOf(s) === -1);
        if (!gp.scopes.length) {
            results = results.filter(p2 => p2.name !== p.name);
        }
    });

    return results;
};

export class PermissionsManager {
    constructor() {
        this.db = MongoClient.connect('mongodb://localhost:27017')
            .then(cli => {
                return cli.db("auth_demo");
            });

        this.permissions = this.db.then(db => db.collection("permissions").find({}).toArray());
        this.scopedPermissions = this.permissions.then(perms => {
            return perms.reduce((result, permission) => {
                const nameSegments = permission.name.split('.');
                const permScope = nameSegments[0];
                if (!result[permScope]) {
                    result[permScope] = [];
                }
                result[permScope].push(permission);
                return result;
            }, {});
        });
        this.scopes = this.scopedPermissions.then(perms => Object.keys(perms));
        this.roles = this.db.then(db => db.collection("roles").find({}).toArray());
        this.userPermissions = {};
    }

    getPermissions() {
        return this.permissions;
    }

    getPermissionsByName(permissionNames) {
        const names = typeof(permissionNames) === 'string' ? [ permissionNames ] : permissionNames;
        if (!Array.isArray(names))
            throw new Error('Requires a permission name or an array of names be supplied');
        if (Array.isEmpty(names))
            return Promise.resolve([]);

        return this.permissions.then(perms => perms.filter(p => names.contains(p.name)));
    }

    getAllFeaturePermissions(includeBetaPermissions = false, betaOnly = false) {
        return this.permissions.then(perms => perms.filter(perm => perm.type === 'feature' && (perm.beta ? includeBetaPermissions : !betaOnly)));
    }

    getAllPermissionsForScope(scopeName) {
        return this.scopedPermissions.then(scoped => scoped[scopeName] || []);
    }

    getRoles() {
        return this.roles;
    }

    getRolePermissions(roleName, showHidden = false) {
        return this.roles.then(roles => {
            const foundRole = roles.find(r => r.name === roleName);
            if (!foundRole)
                return [];
            return foundRole.defaultPermissions.filter(p => showHidden || !p.hidden)});
    }

    getAggregateRolePermissions(rolesList) {
        const permissionsPromises = (rolesList.length === 1 && rolesList[0] === '*')
            ? this.getRoles()
                .then(roles => roles.map(r => this.getRolePermissions(r)))
            : rolesList.map(r => this.getRolePermissions(r));

        return Promise.all(permissionsPromises)
            .then(permissionsArrays => combinePermissions(permissionsArrays));
    }

    computePermissionsSet(roleNames, userPermissions = [], accountPermissions = []) {
        return this.getAggregateRolePermissions(roleNames)
            .then(aggregatePermissions => {
                let allPerms = aggregatePermissions;

                if (!Array.isEmpty(accountPermissions)) {
                    const accountGrants = accountPermissions.filter(p => p.type === 'grant').map(p => ({name: p.name, scopes: p.scope}));
                    if (!Array.isEmpty(accountGrants)) {
                        allPerms = combinePermissions(allPerms, accountGrants);
                    }

                    const accountRevokes = accountPermissions.filter(p => p.type === 'revoke').map(p => ({name: p.name, scopes: p.scope}));
                    if (!Array.isEmpty(accountRevokes)) {
                        allPerms = processRevokes(allPerms, accountRevokes);
                    }
                }

                if (!Array.isEmpty(userPermissions)) {
                    const userGrants = userPermissions.filter(p => p.type === 'grant').map(p => ({name: p.name, scopes: p.scope}));
                    if (!Array.isEmpty(userGrants)) {
                        allPerms = combinePermissions(allPerms, userGrants);
                    }

                    const userRevokes = userPermissions.filter(p => p.type === 'revoke').map(p => ({name: p.name, scopes: p.scope}));
                    if (!Array.isEmpty(userRevokes)) {
                        allPerms = processRevokes(allPerms, userRevokes);
                    }
                }

                return processPermissionsImplies(allPerms, this.permissions);
            });
    }

    computeUserPermissions(user) {
        let userPerms = this.userPermissions[user.userName];
        if (userPerms && (userPerms.roles.length === user.roles.length && userPerms.roles.every(r => user.roles.indexOf(r) !== -1))) {
            return Promise.resolve(userPerms.grants);
        }

        return this.computePermissionsSet(user.roles, user.userSpecificPermissionOverrides, user.account ? user.account.userSpecificPermissionOverrides : null)
            .then(computed => {
                this.userPermissions[user.userName] = {roles: user.roles, grants: computed};
                return computed;
            });
    }

    getApplicationPermissions(user, appName) {
        const accessibleApps = this.getUserAccessibleApplications(user);
        if (!accessibleApps.contains(appName)) {
            return Promise.resolve([]);
        }

        return this.computeUserPermissions(user)
            .then(grants => {
                return grants.filter(p => p.name.startsWith(appName) || p.scopes.contains(appName));
            });
    }

    getUserAccessibleApplications(user) {
        if (user.accessibleApplications !== null)
            return Promise.resolve(user.accessibleApplications);

        const permissionsPromise = user.hasComputedPermissions
            ? Promise.resolve(user.effectivePermissions)
            : (user.userSpecificPermissionOverrides.length === 1 && user.userSpecificPermissionOverrides[0].type === 'grant' && user.userSpecificPermissionOverrides[0].name === '*')
                ? this.permissions.then(allPerms => allPerms.map(p => ({name: p.name, scopes: []})))
                : this.computeUserPermissions(user);

        return permissionsPromise.then(perms => {
            if (!user.hasComputedPermissions)
                user.effectivePermissions = perms;

            const appAccessPerm = perms.find(p => p.name === 'application.access');
            let accessibleApplications = [];

            if (appAccessPerm) {
                accessibleApplications = (Array.isEmpty(appAccessPerm.scopes) || (appAccessPerm.scopes.length === 1 && appAccessPerm.scopes[0] === '*'))
                     ? APPLICATIONS
                     : appAccessPerm.scopes;
            }

            user.accessibleApplications = accessibleApplications;

            return accessibleApplications;
        });
    }
}
