#!/bin/sh
# SPDX-FileCopyrightText: NONE
# SPDX-License-Identifier: GPL-2.0-or-later
# Note: AI-generated contribution; no legal determination implied.

if [ ! -r /dev/binderfs/features/oneway_spam_detection ]; then
	echo "BINDERFS_FEATURE_PATH=SKIP (host feature file unavailable)"
	exit 0
fi

$PROOT -B -0 ./test-binderfs-feature-path
