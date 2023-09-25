const config = require('config.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('_helpers/db');
const Mongoose = require('mongoose');
const User = db.User;

module.exports = {
    authenticate,
    authenticateAuditor,
    getAll,
    getAuditData,
    getById,
    create,
    update,
    delete: _delete,
    upsertLoginAndIp,
    logout
};

async function authenticate({ username, password }) {
    const user = await User.findOne({ username });
    if (user && bcrypt.compareSync(password, user.hash)) {
        const { hash, ...userWithoutHash } = user.toObject();
        const token = jwt.sign({ sub: user.id }, config.secret);
        return {
            ...userWithoutHash,
            token
        };
    }
}

async function authenticateAuditor({ sub: id }) {
    const user = await User.findOne({ _id: Mongoose.Types.ObjectId(id) }, { role: 1 });

    return user && user.role === "AUDITOR";
}

async function upsertLoginAndIp(user, req) {
    if (user) {
        await User.updateOne({ username: user.username }, { $set: { loggedInAt: new Date(Date.now()), ipAddress: req.socket.remoteAddress } });
    }

    return user;
}

async function getAll() {
    return await User.find({}, { firstName: 1, lastName: 1, username: 1 });
}

async function getAuditData() {
    return await User.find({}, { firstName: 1, lastName: 1, username: 1, role: 1, loggedInAt: 1, loggedOutAt: 1, ipAddress: 1 });
}

async function getById(id) {
    return await User.findById(id).select('-hash');
}

async function create(userParam) {
    // validate
    if (await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    const user = new User(userParam);

    // hash password
    if (userParam.password) {
        user.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // save user
    await user.save();
}

async function update(id, userParam) {
    const user = await User.findById(id);

    // validate
    if (!user) throw 'User not found';
    if (user.username !== userParam.username && await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    // hash password if it was entered
    if (userParam.password) {
        userParam.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // copy userParam properties to user
    Object.assign(user, userParam);

    await user.save();
}

async function _delete(id) {
    await User.findByIdAndRemove(id);
}

async function logout(user) {
    await User.updateOne({ username: user.username }, { $set: { loggedOutAt: new Date(Date.now()) } });
}