#!/bin/bash

# branches to check out

branches=("sequoia" "sonoma" "ventura" "monterey" "catalina" "big_sur" "ios_16" "ios_17" "ios_18" "visionos")

for branch in ${branches[@]}; do
    if [[ ! -d "_work/$branch" ]]; then
        mkdir -p "_work/$branch"
    fi

    git --work-tree=_work/$branch checkout $branch -- rules

    git restore --staged .

done