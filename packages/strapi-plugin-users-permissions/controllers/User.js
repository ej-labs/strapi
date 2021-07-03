'use strict';

/**
 * User.js controller
 *
 * @description: A set of functions called "actions" for managing `User`.
 */

const _ = require('lodash');
const { sanitizeEntity } = require('strapi-utils');
const adminUserController = require('./user/admin');
const apiUserController = require('./user/api');

const emailRegExp = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
const usernameRegExp = /^(?=[a-zA-Z0-9._]{3,32}$)(?!.*[_.]{2})[^_.].*[^_.]$/;

const formatError = error => [
  { messages: [{ id: error.id, message: error.message, field: error.field }] },
]

const sanitizeUser = user =>
  sanitizeEntity(user, {
    model: strapi.query('user', 'users-permissions').model,
  });

const resolveController = ctx => {
  const {
    state: { isAuthenticatedAdmin },
  } = ctx;

  return isAuthenticatedAdmin ? adminUserController : apiUserController;
};

const resolveControllerMethod = method => ctx => {
  const controller = resolveController(ctx);
  const callbackFn = controller[method];

  if (!_.isFunction(callbackFn)) {
    return ctx.notFound();
  }

  return callbackFn(ctx);
};

module.exports = {
  create: resolveControllerMethod('create'),
  update: resolveControllerMethod('update'),

  /**
   * Retrieve user records.
   * @return {Object|Array}
   */
  async find(ctx, next, { populate } = {}) {
    let users;

    if (_.has(ctx.query, '_q')) {
      // use core strapi query to search for users
      users = await strapi.query('user', 'users-permissions').search(ctx.query, populate);
    } else {
      users = await strapi.plugins['users-permissions'].services.user.fetchAll(ctx.query, populate);
    }

    ctx.body = users.map(sanitizeUser);
  },

  /**
   * Retrieve a user record.
   * @return {Object}
   */
  async findOne(ctx) {
    const { id } = ctx.params;
    let data = await strapi.plugins['users-permissions'].services.user.fetch({
      id,
    });

    if (data) {
      data = sanitizeUser(data);
    }

    // Send 200 `ok`
    ctx.body = data;
  },

  /**
   * Retrieve user count.
   * @return {Number}
   */
  async count(ctx) {
    if (_.has(ctx.query, '_q')) {
      return await strapi.plugins['users-permissions'].services.user.countSearch(ctx.query);
    }
    ctx.body = await strapi.plugins['users-permissions'].services.user.count(ctx.query);
  },

  /**
   * Destroy a/an user record.
   * @return {Object}
   */
  async destroy(ctx) {
    const { id } = ctx.params;
    const data = await strapi.plugins['users-permissions'].services.user.remove({ id });
    ctx.send(sanitizeUser(data));
  },

  async destroyAll(ctx) {
    const {
      request: { query },
    } = ctx;

    const toRemove = Object.values(_.omit(query, 'source'));
    const { primaryKey } = strapi.query('user', 'users-permissions');
    const finalQuery = { [`${primaryKey}_in`]: toRemove, _limit: 100 };

    const data = await strapi.plugins['users-permissions'].services.user.removeAll(finalQuery);

    ctx.send(data);
  },

  /**
   * Retrieve authenticated user.
   * @return {Object|Array}
   */
  async me(ctx) {
    const user = ctx.state.user;

    if (!user) {
      return ctx.badRequest(null, [{ messages: [{ id: 'No authorization header was found' }] }]);
    }

    const subs =  await strapi
                  .query('sub')
                  .find({ user: user.id},["product","product.picture","pricing_plan","pricing_plan.paygate","pricing_plan.pricing"]);

    ctx.body = sanitizeUser(user);
    ctx.body.subs = subs;
    // add extra info passwordSet
    ctx.body.hasPassword = user.password ? true : false;
  },

  async changePassword(ctx) {
    const params = _.assign({}, ctx.request.body, ctx.params);
    if (
      params.password &&
      params.passwordConfirmation &&
      params.password === params.passwordConfirmation
    ) {
      
      const user = ctx.state.user;

      if (!user) {
        return ctx.badRequest(null, [{ messages: [{ id: 'No authorization header was found' }] }]);
      }

      // The user never authenticated with the `local` provider.
      if (user.password) {
        if(!params.currentPassword)
          return ctx.badRequest(
            null,
            formatError({
              id: 'Auth.form.error.password.invalid',
              message: "current password require.!!"
            })
          );
      
        const validPassword = await strapi.plugins[
          'users-permissions'
        ].services.user.validatePassword(params.currentPassword, user.password);
  
        if (!validPassword) {
          return ctx.badRequest(
            null,
            formatError({
              id: 'Auth.form.error.invalid',
              message: 'password invalid.',
            })
          );
        }
      }

      const password = await strapi.plugins['users-permissions'].services.user.hashPassword({
        password: params.password,
      });

      // Update the user.
      await strapi
        .query('user', 'users-permissions')
        .update({ id: user.id }, { resetPasswordToken: null, password });

      ctx.send({
        "success": true
      });
    } else if (
      params.password &&
      params.passwordConfirmation &&
      params.password !== params.passwordConfirmation
    ) {
      return ctx.badRequest(
        null,
        formatError({
          id: 'Auth.form.error.password.matching',
          message: 'Passwords do not match.',
        })
      );
    } else {
      return ctx.badRequest(
        null,
        formatError({
          id: 'Auth.form.error.params.provide',
          message: 'Incorrect params provided.',
        })
      );
    }
  },

  async updateProfile(ctx) {
    const user = ctx.state.user;
    if (!user) {
      return ctx.badRequest(null, [{ messages: [{ id: 'No authorization header was found' }] }]);
    }
    
    const advancedConfigs = await strapi
      .store({
        environment: '',
        type: 'plugin',
        name: 'users-permissions',
        key: 'advanced',
      })
      .get();

    const { id } = user;
    const { email, username, password } = ctx.request.body;

    if (_.has(ctx.request.body, 'email') && !email) {
      return ctx.badRequest('email.notNull');
    }

    if(email && !emailRegExp.test(email)) {
      return ctx.badRequest('email.invalid');
    }
    
    // Check if the provided identifier is an email or not.
    
    if (_.has(ctx.request.body, 'username') && !username) {
      return ctx.badRequest('username.notNull');
    }
    
    if(username && !usernameRegExp.test(username)) {
      return ctx.badRequest('username.invalid');
    }

    if (_.has(ctx.request.body, 'password') && !password && user.provider === 'local') {
      return ctx.badRequest('password.notNull');
    }

    if (_.has(ctx.request.body, 'username')) {
      const userWithSameUsername = await strapi
        .query('user', 'users-permissions')
        .findOne({ username });

      if (userWithSameUsername && userWithSameUsername.id != id) {
        return ctx.badRequest(
          null,
          formatError({
            id: 'Auth.form.error.username.taken',
            message: 'username.alreadyTaken.',
            field: ['username'],
          })
        );
      }
    }

    if (_.has(ctx.request.body, 'email') && advancedConfigs.unique_email && email !== user.email) {
      if(user.confirmed) {
        return ctx.badRequest(
          null,
          formatError({
            id: 'Auth.form.error.email.taken_confirmed',
            message: 'Cannot change confirmed email',
            field: ['email'],
          })
        );
      }

      const userWithSameEmail = await strapi.query('user', 'users-permissions').findOne({ email: email.toLowerCase() });

      if (userWithSameEmail && userWithSameEmail.id != id) {
        return ctx.badRequest(
          null,
          formatError({
            id: 'Auth.form.error.email.taken',
            message: 'Email already taken',
            field: ['email'],
          })
        );
      }

      

      ctx.request.body.email = ctx.request.body.email.toLowerCase();
    }

    let updateData = {
      ...ctx.request.body,
    };
    
    // ignore private field 
    delete updateData.password
    delete updateData.provider
    delete updateData.providerData
    delete updateData.confirmed
    delete updateData.role

    if(updateData.email && updateData.email !== user.email) {
      updateData.confirmed = false
    }

    const data = await strapi.plugins['users-permissions'].services.user.edit({ id }, updateData);

    ctx.send(sanitizeUser(data));
  },


  async uploadPhoto(ctx) {
    const user = ctx.state.user;
    if (!user) {
      return ctx.badRequest(null, [{ messages: [{ id: 'No authorization header was found' }] }]);
    }
    
    if (!ctx.request.files || !ctx.request.files.photoURL) {
      return ctx.badRequest(null, [{ messages: [{ id: 'No Files was found' }] }]);
    }
    const file = ctx.request.files.photoURL;
    
    const { id } = user;
    const fileup = await strapi.plugins.upload.services.upload.uploadToModel({ id, model:"user", field: "photoURL" ,path: "avatar" }, file, "users-permissions");
    

    const data = await strapi.plugins['users-permissions'].services.user.edit({ id }, {
      photoURL: fileup.url,
      customPhoto: true
    });
    ctx.send(data);
  },
};
