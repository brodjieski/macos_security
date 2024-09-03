#!/bin/bash

# branches to check out

branches=("sonoma" "ventura" "monterey" "catalina" "big_sur")

for branch in ${branches[@]}; do
    if [[ ! -d "_work/$branch" ]]; then
        mkdir -p "_work/$branch"
    fi

    git --work-tree=_work/$branch checkout $branch -- rules

    git restore --staged .

done