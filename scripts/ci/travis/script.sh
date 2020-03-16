#!/bin/bash

set -ev

if [ "$TRAVIS_OS_NAME" = "osx" ]; then
    # preventing "No output has been received in the last 10m0s" error occuring on travis-ci
    # see https://github.com/travis-ci/travis-ci/issues/4190#issuecomment-353342526
    # output something every 9 minutes (540 seconds) to prevent Travis killing the job
    while sleep 540; do echo "=====[ $SECONDS seconds still running ]====="; done &
        yarn run lib
    # killing background sleep loop
    kill %1
else
    yarn run lib
fi
