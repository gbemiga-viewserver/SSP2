#!/bin/sh

if which ninja >/dev/null; then
    cmake -B build -G Ninja $1 && \
    ninja -C build $1
else
    cmake -B build $1 && \
    make -j $(getconf _NPROCESSORS_ONLN) -C build $1 && \
    echo "done. Diggidy done !!"
fi
exit $?