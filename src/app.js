import getRawBody from 'raw-body'
import got from 'got'
import http from 'http'
import jwt from 'jsonwebtoken'
import { promisify } from 'util'
import sqlite from 'better-sqlite3'

require('dotenv').config()

const envPort = parseInt(process.env.APP_PORT, 10)
const envDiscordId = process.env.APP_DISCORD_ID
const envDiscordSecret = process.env.APP_DISCORD_SECRET
const envApiOrigin = process.env.APP_API_ORIGIN
const envPlayOrigin = process.env.APP_PLAY_ORIGIN
const envTokenSecret = process.env.APP_TOKEN_SECRET

const jwtSign = promisify(jwt.sign.bind(jwt))
const jwtVerify = promisify(jwt.verify.bind(jwt))

const db = sqlite('data/db.sqlite3')
db.defaultSafeIntegers(true)
db.pragma('journal_mode = WAL')

const flags = {
  DEV: 1 << 0,
  MOD: 1 << 1,
  BETA: 1 << 2
}

const factions = {
  PHOENIX_RIDERS: 0,
  WINTER_DRAGONS: 1,
  DEMON_BRIGADE: 2
}

const factionIds = {}
Object.entries(factions).forEach(([key, id]) => {
  factionIds[id] = key
})

db.exec(
  'create table if not exists users (id integer primary key not null, name text not null, avatar text, access_token text not null, refresh_token text not null, flags integer not null, faction integer)'
)

const registerStatement = db.prepare(
  'insert into users (id, name, avatar, access_token, refresh_token, flags, faction) values(?, ?, ?, ?, ?, ?, ?)'
)
const getUserStatement = db.prepare('select id, name, avatar, flags, faction from users where id=?')
const editFactionStatement = db.prepare('update users set faction=? where id=?')
const editLoginStatement = db.prepare(
  'update users set name=?, avatar=?, access_token=?, refresh_token=? where id=?'
)

http
  .createServer(async (req, res) => {
    try {
      const splitUrl = req.url.split('?', 2)
      let params
      if (splitUrl[1] === undefined) {
        params = new URLSearchParams('')
      } else {
        params = new URLSearchParams(splitUrl[1])
      }
      if (splitUrl[0].endsWith('/')) {
        splitUrl[0] = splitUrl[0].slice(0, -1)
      }
      const sendError = (status, message) => {
        res.writeHead(status, {
          'content-type': 'application/json'
        })
        res.end(
          JSON.stringify({
            message
          })
        )
      }
      if (splitUrl[0] === '/v1/login' && req.method === 'GET') {
        if (params.get('code') === null) {
          res.writeHead(302, {
            location: `https://discordapp.com/api/oauth2/authorize?client_id=${envDiscordId}&redirect_uri=${envApiOrigin}/v1/login&response_type=code&scope=identify&prompt=none`
          })
          res.end('')
        } else {
          let userData
          let tokenRes
          try {
            tokenRes = JSON.parse(
              (
                await got({
                  url: 'https://discordapp.com/api/v6/oauth2/token',
                  method: 'POST',
                  form: {
                    client_id: envDiscordId,
                    client_secret: envDiscordSecret,
                    grant_type: 'authorization_code',
                    code: params.get('code'),
                    redirect_uri: `${envApiOrigin}/v1/login`,
                    scope: 'identify'
                  }
                })
              ).body
            )
            userData = JSON.parse(
              (
                await got({
                  url: 'https://discordapp.com/api/v6/users/@me',
                  headers: {
                    authorization: `Bearer ${tokenRes.access_token}`
                  }
                })
              ).body
            )
          } catch (e) {
            sendError(403, 'Discord authentication failed.')
            return
          }
          const editResult = editLoginStatement.run(
            userData.username,
            userData.avatar,
            tokenRes.access_token,
            tokenRes.refresh_token,
            sqlite.Integer(userData.id)
          )
          if (editResult.changes === 0) {
            registerStatement.run(
              sqlite.Integer(userData.id),
              userData.username,
              userData.avatar,
              tokenRes.access_token,
              tokenRes.refresh_token,
              0,
              null
            )
          }
          const token = await jwtSign(
            {
              id: userData.id,
              iss: 'zeiw:login'
            },
            envTokenSecret,
            {
              noTimestamp: true
            }
          )
          res.writeHead(302, {
            location: `${envPlayOrigin}/cb.html?uc=${encodeURIComponent(token)}`
          })
          res.end('')
        }
      } else if (splitUrl[0] === '/v1/user') {
        let tokenData
        try {
          tokenData = await jwtVerify(req.headers.authorization, envTokenSecret, {
            issuer: 'zeiw:login'
          })
        } catch (e) {
          sendError(403, 'Invalid token.')
          return
        }
        if (req.method === 'GET') {
          const user = getUserStatement.get(sqlite.Integer(tokenData.id))
          if (user === undefined) {
            sendError(404, 'User not found.')
            return
          }
          res.writeHead(200, {
            'content-type': 'application/json'
          })
          let avatar = 'https://zeiw.pnfc.re/play/images/default.png'
          if (user.avatar !== null) {
            avatar = `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}`
          }
          let userOutFlags = []
          const userDbFlags = user.flags.toNumber()
          Object.entries(flags).forEach(([key, flag]) => {
            if ((userDbFlags & flag) !== 0) {
              userOutFlags.push(key)
            }
          })
          if (user.faction !== null) {
            userOutFlags.push(factionIds[user.faction.toNumber()])
          }
          res.end(
            JSON.stringify({
              uid: user.id.toString(),
              uname: user.name,
              avatar,
              flags: userOutFlags,
              stats: {}
            })
          )
        } else if (req.method === 'PATCH') {
          if (req.headers['content-type'] !== 'application/json') {
            sendError(400, 'Request body must be valid JSON.')
          }
          let body
          try {
            body = JSON.parse(await getRawBody(req))
          } catch (e) {
            sendError(400, 'Body parsing error.')
            return
          }
          if (
            typeof body !== 'object' ||
            body === null ||
            typeof body.faction !== 'number' ||
            !Number.isInteger(body.faction) ||
            body.faction < 0 ||
            body.faction > 2
          ) {
            sendError(400, 'Invalid faction.')
            return
          }
          const factionResult = editFactionStatement.run(body.faction, sqlite.Integer(tokenData.id))
          if (factionResult.changes === 0) {
            sendError(404, 'User not found.')
            return
          }
          res.writeHead(204)
          res.end()
        } else {
          sendError(405, 'Method not found.')
        }
      } else {
        sendError(404, 'Endpoint not found.')
      }
    } catch (e) {
      console.error(e)
      sendError(500, 'Internal server error.')
    }
  })
  .listen(envPort, '127.0.0.1', () => {
    console.log(`🚀 Server ready at http://localhost:${envPort}/`)
  })
