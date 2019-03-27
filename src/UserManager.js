import MongoClient, {ObjectId} from 'mongodb';

import {PermissionsManager} from './PermissionsManager';
import { User } from './User';

const symUsers = Symbol('users');
const symPermissionsManager = Symbol('permissionsManager');

export class UserManager {
    constructor() {
        this.collection = MongoClient.connect('localhost')
            .then(cli => {
                return cli.db("auth_demo").collection('users');
            });

        this[symUsers] = {};
        this[symPermissionsManager] = new PermissionsManager();
    }

    getUser(username) {
        let user = this[symUsers][username];
        if (user) {
            return Promise.resolve(user);
        }
        return this.collection.findOne({userName: username}).then(u => {
            if (!u)
                return null;

            user = new User(u);

            this[symUsers][username] = user;

            return user;
        });
    }

    getUserById(userId) {
        let user = Object.values(this[symUsers]).find(u => u.id === userId);
        if (user) {
            return Promise.resolve(user);
        }
        return this.collection.findOne({_id: ObjectId(userId)}).then(u => {
            if (!u)
                return null;

            user = new User(u, this[symPermissionsManager]);

            this[symUsers][user.username] = user;

            return user;
        });
    }

    findUsersWithRole(roleName) {
        return this.collection.find({roles: roleName}).then(users => {
            return users.map(u => {
                let user = this[symUsers][u.userName];

                if (user)
                    return user;

                user = new User(u, this[symPermissionsManager]);

                this[symUsers][u.userName] = user;

                return user;
            });
        });
    }

    userHasRole(username, roleName) {
        return this.getUser(username)
            .then(user => {
                if (!user) {
                    throw new Error(`No user "${username}" could be found!`);
                }

                return user.hasRole(roleName);
            });
    }

    userHasPermission(username, permissionName, scope = null) {
        return this.getUser(username)
            .then(user => {
                if (!user) {
                    throw new Error(`No user "${username}" could be found!`);
                }

                return user.hasPermission(permissionName, scope);
            });
    }

    deactiveUser(user) {
        if (user.protected)
            throw new Error(`User "${user.username}" is a protected account and cannot be altered!`);

        const userId = user.id;

        return this.collection.updateOne({_id: ObjectId(userId)}, { '$set': {active: false}})
            .then(res => true)
            .catch(err => {
                console.error(`Error updating user "${user.username}": ${err}`);
                return false;
            });
    }

    saveUser(user) {
        if (user.protected)
            throw new Error(`User "${user.username}" is a protected account and cannot be altered!`);

        const rawUserData = user.rawData;

        const toUpdate = { ...rawUserData, roles: user.roles, permissions: user.userSpecificPermissionOverrides };

        return this.collection.save(toUpdate)
            .then(res => true)
            .catch(err => {
                console.error(`Error updating user "${user.username}": ${err}`);
                return false;
            });
    }
}
