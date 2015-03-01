#!/usr/bin/env bash

echo "Running tests..."

for i in $(ls -d build/tests/*); do
	echo "Test: $i"
	./$i
	if [ "$?" -ne "0" ]; then
		exit 1
	fi
	echo ""
done

echo "Done."

