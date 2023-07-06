#!/bin/bash

# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: GPL-2.0-only

set -eu

INDIR=$1
OUTDIR=$2

ARGS=(
	"--annotate" # Add comments to the xml output
	"--no-corpus-path" # Do not put the path in the abi-corpus
)

for lib in "${INDIR}"/liblttng-ust*.so.?
do
	abidw "${ARGS[@]}" --out-file "${OUTDIR}/$(basename "$lib").xml" "$lib"

	# Clean the full paths
	sed -i "s#$(pwd)/##g" "${OUTDIR}/$(basename "$lib").xml"
done

