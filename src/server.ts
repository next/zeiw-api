import { FACTIONS, FLAGS } from "./utils/constants"
import jwt, { Secret } from "jsonwebtoken"

import { config } from "./config"
import { getFlags } from "./utils/helpers"
import getRawBody from "raw-body"
import got from "got"
import http from "http"
import sqlite from "better-sqlite3"

const db = sqlite("data/db.sqlite3")
db.defaultSafeIntegers(true)
db.pragma("journal_mode = WAL")

const factionIds: any = {}
Object.entries(FACTIONS).forEach(([key, id]) => (factionIds[id] = key))

db.exec(
	"create table if not exists users (id integer primary key not null, name text not null, avatar text, access_token text not null, refresh_token text not null, flags integer not null, faction integer)",
)

const registerStatement = db.prepare(
	"insert into users (id, name, avatar, access_token, refresh_token, flags, faction) values(?, ?, ?, ?, ?, ?, ?)",
)
const getUserStatement = db.prepare(
	"select id, name, avatar, flags, faction from users where id=?",
)
const editFactionStatement = db.prepare("update users set faction=? where id=?")
const editLoginStatement = db.prepare(
	"update users set name=?, avatar=?, access_token=?, refresh_token=? where id=?",
)

http
	.createServer(async (req, res) => {
		function sendError(status: number, message: string) {
			res.writeHead(status, { "content-type": "application/json" })
			res.end(JSON.stringify({ message }))
		}

		try {
			const splitUrl = req.url!.split("?", 2) || null

			let params: URLSearchParams

			if (splitUrl[1] === undefined) {
				params = new URLSearchParams("")
			} else {
				params = new URLSearchParams(splitUrl[1])
			}

			if (splitUrl[0].endsWith("/")) splitUrl[0] = splitUrl[0].slice(0, -1)

			if (splitUrl[0] === "/v1/login" && req.method === "GET") {
				if (!params.get("code")) {
					res.writeHead(302, {
						location: `https://discord.com/api/oauth2/authorize?client_id=${config.discordId}&redirect_uri=${config.apiOrigin}/v1/login&response_type=code&scope=identify&prompt=none`,
					})
					return res.end("")
				}

				let tokenRes: { access_token: string; refresh_token: string }
				let userData: { username: string; avatar: string; id: string }

				try {
					tokenRes = JSON.parse(
						(
							await got({
								url: "https://discord.com/api/v6/oauth2/token",
								method: "POST",
								form: {
									client_id: config.discordId,
									client_secret: config.discordSecret,
									code: params.get("code"),
									grant_type: "authorization_code",
									redirect_uri: `${config.apiOrigin}/v1/login`,
									scope: "identify",
								},
							})
						).body,
					)

					userData = JSON.parse(
						(
							await got({
								url: "https://discord.com/api/v6/users/@me",
								headers: {
									authorization: `Bearer ${tokenRes.access_token}`,
								},
							})
						).body,
					)
				} catch {
					return sendError(403, "Discord authentication failed")
				}

				const editResult = editLoginStatement.run(
					userData.username,
					userData.avatar,
					tokenRes.access_token,
					tokenRes.refresh_token,
					BigInt(userData.id),
				)

				if (!editResult.changes) {
					registerStatement.run(
						BigInt(userData.id),
						userData.username,
						userData.avatar,
						tokenRes.access_token,
						tokenRes.refresh_token,
						0,
						null,
					)
				}

				const token = jwt.sign(
					{ id: userData.id, iss: "zeiw:login" },
					config.tokenSecret as Secret,
					{ noTimestamp: true },
				)

				res.writeHead(302, {
					location: `${config.playOrigin}/cb.html?uc=${encodeURIComponent(
						token,
					)}`,
				})
				return res.end("")
			}

			if (splitUrl[0] === "/v1/user") {
				let tokenData: any

				try {
					tokenData = jwt.verify(
						req.headers.authorization!,
						config.tokenSecret as Secret,
						{ issuer: "zeiw:login" },
					)
				} catch {
					return sendError(403, "Invalid token")
				}

				if (req.method === "GET") {
					const user = getUserStatement.get(BigInt(tokenData.id))

					if (!user) return sendError(404, "User not found")

					res.writeHead(200, { "content-type": "application/json" })

					let avatar = "https://zeiw.pnfc.re/play/images/default.png"

					if (user.avatar !== null)
						avatar = `https://cdn.discord.com/avatars/${user.id}/${user.avatar}`

					let flags = getFlags(user?.flags, FLAGS)

					if (user.faction !== null) {
						flags.push(factionIds[Number(user.faction)])
					}

					return res.end(
						JSON.stringify({
							avatar,
							flags,
							uid: user.id.toString(),
							uname: user.name,
						}),
					)
				}

				if (req.method === "PATCH") {
					if (req.headers["content-type"] !== "application/json") {
						sendError(400, "Request body must be valid JSON")
					}

					let body: { faction: number }

					try {
						body = JSON.parse((await getRawBody(req)).toString())
					} catch {
						return sendError(400, "Unable to parse JSON")
					}

					if (
						typeof body !== "object" ||
						body === null ||
						typeof body.faction !== "number" ||
						!Number.isInteger(body.faction) ||
						body.faction < 0 ||
						body.faction > 2
					) {
						return sendError(400, "Invalid faction")
					}

					const factionResult = editFactionStatement.run(
						body.faction,
						BigInt(tokenData.id),
					)

					if (!factionResult.changes) return sendError(404, "User not found")

					res.writeHead(204)
					return res.end()
				}

				sendError(405, "Method not found")
			} else {
				sendError(404, "Endpoint not found")
			}
		} catch (e) {
			console.error(e)
			return sendError(500, "Internal server error")
		}
	})
	.listen(config.port, () => {
		console.log(`> Running @ http://localhost:${config.port}`)
	})
