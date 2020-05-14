zig build

FILE=/zig-cache/bin/zls

if test -f "$FILE"; then
	exit 0
else
	exit 1
fi
