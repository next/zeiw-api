require("dotenv").config()

export const config = {
	apiOrigin: process.env.APP_API_ORIGIN,
	discordId: process.env.APP_DISCORD_ID,
	discordSecret: process.env.APP_DISCORD_SECRET,
	playOrigin: process.env.APP_PLAY_ORIGIN,
	port: parseInt(process.env.APP_PORT!, 10),
	tokenSecret: process.env.APP_TOKEN_SECRET,
}
