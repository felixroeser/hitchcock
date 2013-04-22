{EventEmitter} = require 'events'

fs        = require 'fs'
http      = require 'http'
httpProxy = require 'http-proxy'
colors    = require 'colors'
mysql     = require 'mysql'
moment    = require 'moment'
url       = require 'url'

module.exports = class Hitchcock extends EventEmitter 
  constructor: (opts={}) ->
    @realm = opts.realm || 'TOUT'

    @resourceOwnerMapper = opts.resourceOwnerMapper || {
      table: 'users',
      fields: ['uid']
    }

    @dbConfig = opts.mysql || {
      database: 'hitchcock_development',
      user:     'root',
      socketPath: '/var/run/mysqld/mysqld.sock'
    }
    @dbpool = mysql.createPool @dbConfig

    @routerConfig = opts.router || {
      '': '127.0.0.1:3000'
    }

    @port = opts.port || 9000

    # httpProxy.ProxyTable.prototype.getProxyLocation.toString()
    @proxy = new httpProxy.RoutingProxy {
      enable: {
        xforward: true
      },
      pathnameOnly: true,
      router: @routerConfig 
    }

    # monkeypatching http-proxy; similar to
    # https://github.com/Zariel/node-http-proxy/blob/001f7508eadb7f6af2c7268ebe84f5c0732495e1/lib/node-http-proxy/proxy-table.js
    @proxy.proxyTable.getProxyLocation = (req)->
      return null if (!req or !req.headers or !req.headers.host)

      target = req.url
      for route in this.routes
        if target.match(route.source.regexp)
          req.url = url.format(target)

          return {
            protocol: route.target.url.protocol.replace(':', ''),
            host: route.target.url.hostname,
            port: route.target.url.port || (this.target.https ? 443 : 80)
          }

      return null

    @server = http.createServer (request, response) =>
      buffer = httpProxy.buffer request
      handleRequest {req: request, res: response}, {dbpool: @dbpool, realm: @realm, resourceOwnerMapper: @resourceOwnerMapper}, (err, result) =>
        if !err and result
          @proxy.proxyRequest request, response, {buffer: buffer}
          # FIXME remove headers
        else
          response.writeHead 401, {"Content-Type": "application/json"}
          response.write JSON.stringify {error: 'unauthorized'}
          response.end()

  handleRequest = (data, opts={}, next) =>
    # {"Authorization"=>"Bearer abcd"
    token = if data.req.headers.authorization
      data.req.headers.authorization.split(' ').reverse()[0]
    else
      url.parse(data.req.url, true).query.access_token

    console.log ['Proxy for', data.req.url, token].join(' ').yellow

    return next 'no_token_present' unless token?
  
    queryVerifyToken = (conn, token, cb) ->
      console.log err if err?
      sql = "SELECT `oauth_access_tokens`.* FROM `oauth_access_tokens` WHERE `oauth_access_tokens`.`token` = '#{token}' LIMIT 1"
      conn.query sql, (err, rows) ->

        if err?
          return cb and cb err, null
        else if rows.length isnt 1
          return cb and cb 'token_not_found', null
        else
          token = (rows || [])[0]
          tokenValid = !token.revoked_at? \
            and token.expires_in \
            and moment(token.created_at).add('seconds', token.expires_in || 0).isAfter(moment())

          return cb and cb !tokenValid, token

    queryResourceOwner = (conn, token, cb) ->
      table = opts.resourceOwnerMapper.table
      sql = "SELECT #{['id'].concat(opts.resourceOwnerMapper.fields).join(', ')} FROM `#{table}` WHERE `#{table}`.`id` = '#{token.resource_owner_id}' LIMIT 1"
      conn.query sql, (err, user) ->
        if err? or user.length isnt 1
          return cb and cb 'resource_owner_not_found'
        else
          user = user[0]

          return cb and cb null, user

    opts.dbpool.getConnection (err, conn) ->

      queryVerifyToken conn, token, (err, token) ->
        # console.log [err, token]

        if err or !token
          conn.end()
          return next and next true, null

        queryResourceOwner conn, token, (err, resourceOwner) ->
          conn.end()

          # WAS return next and next true, null if err or !resourceOwner
          resourceOwner or= {}

          data.res.setHeader "X-HITCHCOCK-#{opts.realm}-SCOPES", token.scopes            
          for field in opts.resourceOwnerMapper.fields
            data.res.setHeader "X-HITCHCOCK-#{opts.realm}-RESOURCE-OWNER-#{field.toUpperCase()}", resourceOwner[field]

          next null, true

  start: ->
    @server.listen @port, '0.0.0.0'
    @.emit 'started'