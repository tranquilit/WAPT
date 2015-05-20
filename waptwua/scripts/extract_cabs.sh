#!/bin/sh

warn() {
    printf "$@" >&2
    printf '\n' >&2
}

die() {
    warn "$@"
    exit 1
}

if [ $# -ne 1 ]; then
    die "Wrong number of args"
fi

dir=$1

if ! [ -d "$dir" ]; then
    die "%s is not a directory" "$dir"
fi

if ! [ -f "$dir/wsusscan2.cab" ]; then
    die "%s does not contain a wsusscan2.cab file" "$dir"
fi

packages=$dir/packages

mkdir -p "$packages" || die "could not create %s" "$packages"

cabextract -d "$packages" "$dir/wsusscan2.cab" || die "cabextract failed"

for cab in "$packages"/*.cab; do
    rm -Rf "${cab%.cab}"
    mkdir "${cab%.cab}" || die "could not create %s" "${cab%.cab}"
    cabextract -d "${cab%.cab}" "$cab" || warn "cabextract failed on %s" "$cab"
done
