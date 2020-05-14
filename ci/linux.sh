zig build

FILE=/zig-cache/bin/zls

if test -f "$FILE"; then
	exit 0
fi
exit 1
