'use strict';

const Hapi = require('hapi');
const Joi = require('joi');
const Basic = require('hapi-auth-basic');
const Bcrypt = require('bcrypt');
const saltRounds = 10;
const mongoose = require('mongoose');

const server = new Hapi.Server();

const dbUrl = 'hapiauth:happy16@ds019633.mlab.com:19633/hapiauth';

server.connection({
    host: 'localhost',
    port: 3000
});

var userSchema = mongoose.Schema({
        firstname: String,
        lastname: String,
        email: String,
        password: String
    },
    {
        versionKey: false
    });

var User = mongoose.model('User', userSchema);

const signupValidation = {
    firstname: Joi.string().max(50).required(),
    lastname: Joi.string().max(50).required(),
    email: Joi.string().email().max(100).required(),
    password: Joi.string().min(8).max(16).required(),
    passwordRe: Joi.any().valid(Joi.ref('password'))
};

const passwordValidation = {
    password: Joi.string().min(8).max(16).required(),
    passwordRe: Joi.any().valid(Joi.ref('password'))
};

const validate = function (request, username, password, callback) {
    User.findOne({
        $or: [
            {email: username}
        ]
    }, function (err, user) {
        if (!user) {
            return callback(null, false);
        }

        if (Bcrypt.compareSync(password, user.password)) {
            callback(null, true, {user: user});
        } else {
            callback(null, false);
        }
    });
};

server.register([require('vision'), Basic], function (err) {

    if (err) {
        console.log('Error: ' + err);
        throw err;
    }

    server.auth.strategy('validateLogin', 'basic', {validateFunc: validate});

    server.views({
        engines: {
            html: require('handlebars')
        },
        relativeTo: __dirname,
        path: './views'
    });

    server.route({
        method: 'GET',
        path: '/',
        handler: function (request, reply) {
            reply.view('index', {title: 'Home'});
        }
    });

    server.route({
        method: 'GET',
        path: '/signup',
        handler: function (request, reply) {
            reply.view('signup', {title: 'Signup'});
        }
    });

    server.route({
        method: 'POST',
        path: '/user',
        handler: function (request, reply) {

            const user = new User();

            user.firstname = request.payload.firstname;
            user.lastname = request.payload.lastname;
            user.email = request.payload.email;

            user.password = Bcrypt.hashSync(request.payload.password, saltRounds);

            user.save(function (err) {
                if (err) {
                    throw err;
                }

                reply.view('signup-success', {title: 'Success'});
            });
        },
        config: {
            payload: {
                output: 'data'
            },
            validate: {
                payload: signupValidation,
                failAction: function (request, reply, error) {
                    reply.view('error', {error: error});
                }
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/login',
        config: {
            auth: 'validateLogin',
            handler: function (request, reply) {
                reply.view('login-success', {title: request.auth.credentials.user.firstname + " " + request.auth.credentials.user.lastname});

            }
        }
    });

    server.route({
        method: 'GET',
        path: '/login/reset',
        handler: function (request, reply) {
            reply.view('reset', {title: 'Password Reset'});
        }
    });

    server.route({
        method: 'POST',
        path: '/login/reset-pass',
        config: {
            payload: {
                output: 'data'
            },
            validate: {
                payload: passwordValidation,
                failAction: function (request, reply, error) {
                    reply.view('error', {error: error});
                }
            },
            auth: 'validateLogin',
            handler: function (request, reply) {

                User.findById(request.auth.credentials.user._id, function (err, user) {
                    if (err) return handleError(err);

                    user.password = Bcrypt.hashSync(request.payload.password, saltRounds);
                    ;
                    user.save(function (err) {
                        if (err) return handleError(err);
                        reply.view('reset-success');
                    });
                });
            }
        }
    });
});

server.start(function (err) {

    if (err) {
        console.log('Error: ' + err);
        throw err;
    }

    console.log('Server running at: ' + server.info.uri);

    mongoose.connect(dbUrl, function (err) {
        if (err) {
            console.log('Error: ' + err);
            throw err;
        }
    });

    console.log("MongoDB Connection Successfull.")
});