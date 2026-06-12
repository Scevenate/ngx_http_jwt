#!/bin/bash
TEST_ROOT=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

rm -rf "$TEST_ROOT/build"
mkdir "$TEST_ROOT/build"

cd "$TEST_ROOT/../../nginx" || exit 1

./auto/configure \
--build="JWT test build" \
--builddir="$TEST_ROOT/build" \
--with-cc-opt="-I /usr/local/include" \
--with-ld-opt="-L /usr/local/lib" \
--add-module="$TEST_ROOT/../src" \
--with-debug

make || exit 1

mkdir -p "$TEST_ROOT/build/logs" || exit 1