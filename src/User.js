import './utils';

const symRawData = Symbol('rawData');
const symEffectivePerms = Symbol('effectivePermissions');
const symAccessibleApps = Symbol('accessibleApplications');
const symAppPermissions = Symbol('accessibleApplicationPermissions');
const symPermissionsManager = Symbol('permissionsManager');

export class User {
    constructor(userdata, permissionsManager) {
        this[symRawData] = userdata;
        this[symEffectivePerms] = null;
        this[symAccessibleApps] = null;
        this[symAppPermissions] = {};
        this[symPermissionsManager] = permissionsManager;
    }

    get rawData() { return this[symRawData]; }

    get id() { return this[symRawData]._id.toString(); }

    get username() { return this[symRawData].userName; }
    set username(val) { this[symRawData].userName = val; }

    get roles() { return this[symRawData].roles; }

    get active() { return !!this[symRawData].active; }
    set active(val) { this[symRawData].active = val; }

    get protected() { return !!this[symRawData].protected; }
    set protected(val) { this[symRawData].protected = val; }

    get hidden() { return !!this[symRawData].hidden; }
    set hidden(val) { this[symRawData].hidden = val; }

    get userSpecificPermissionOverrides() { return this[symRawData].permissions; }


    set effectivePermissions(val) { this[symEffectivePerms] = val; }

    get accessibleApplications() { return this[symAccessibleApps]; }
    set accessibleApplications(val) { this[symAccessibleApps] = val; }

    get hasComputedPermissions() { return !Array.isEmpty(this[symEffectivePerms]); }

    get userScopedPermissionGrants() {
        return this.userSpecificPermissionOverrides.filter(p => p.type === 'grant').map(p => ({name: p.name, scopes: p.scopes}));
    }

    get userScopedPermissionRevokes() {
        return this.userSpecificPermissionOverrides.filter(p => p.type === 'revoke').map(p => ({name: p.name, scopes: p.scopes}));
    }

    hasRole(roleName) {
        return !!this.roles.find(r => r === roleName);
    }

    addRole(roleName) {
        if (this.roles.contains(roleName))
            return;
        this.roles.push(roleName);
    }

    removeRole(roleName) {
        this[symRawData].roles = this.roles.filter(r => r !== roleName);
    }

    grantPermission(permissionName, scopes = []) {
        const existing = this.userSpecificPermissionOverrides.find(p => p.name === permissionName);
        if (!existing) {
            this.userSpecificPermissionOverrides.push({ type: 'grant', name: permissionName, scopes });
            return;
        }

        if (existing.type === 'revoke') {
            existing.type = 'grant';
            existing.scopes = scopes;
            return;
        }

        existing.scopes = [ ...new Set(existing.scopes.concat(scopes)) ];
    }

    revokePermission(permissionName, scopes = []) {
        const existing = this.userSpecificPermissionOverrides.find(p => p.name === permissionName);
        if (!existing) {
            this.userSpecificPermissionOverrides.push({ type: 'revoke', name: permissionName, scopes });
            return;
        }

        if (existing.type === 'grant') {
            if (Array.isEmpty(scopes)) {
                existing.type = 'revoke';
                existing.scopes = scopes;
                return;
            }

            existing.scopes = existing.scopes.filter(s => !scopes.contains(s));
            if (Array.isEmpty(existing.scopes)) {
                existing.type = 'revoke';
                existing.scopes = scopes;
            }
        }

        existing.scopes = [ ...new Set(existing.scopes.concat(scopes)) ];
    }

    hasPermission(permissionName, scope = null) {
        return this.getEffectivePermissionsSet()
            .then(perms => {
                const foundPerm = perms.find(p => p.name === permissionName);
                if (!foundPerm)
                    return false;

                if (scope && !foundPerm.scopes.contains(scope))
                    return false;

                return true;
            });
    }

    findAccessibleApplications() {
        if (!Array.isEmpty(this.accessibleApplications))
            return Promise.resolve(this.accessibleApplications);

        return this[symPermissionsManager].getUserAccessibleApplications(this)
            .then(apps => {
                this[symAccessibleApps] = apps;
                return apps;
            });
    }

    findApplicationPermissions(applicationName) {
        const foundPerms = this[symAppPermissions][applicationName];
        if (foundPerms)
            return Promise.resolve(foundPerms);

        return this[symPermissionsManager].getApplicationPermissions(this, applicationName)
            .then(perms => {
                this[symAppPermissions][applicationName] = perms;
                return perms;
            });
    }

    getEffectivePermissionsSet() {
        if (this[symEffectivePerms])
            return Promise.resolve(this[symEffectivePerms]);

        return this[symPermissionsManager].computeUserPermissions(this)
            .then(computedPermissions => {
                this[symEffectivePerms] = computedPermissions;
                return computedPermissions;
            });
    }
}
