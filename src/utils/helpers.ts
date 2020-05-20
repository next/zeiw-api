type keyValue = { [key: string]: number }

export function getFlags(flags: number, flagsObject: keyValue) {
	const outFlags: string[] = []

	Object.entries(flagsObject).forEach(([key, value]) => {
		if (flags & value) outFlags.push(key)
	})

	return outFlags
}
