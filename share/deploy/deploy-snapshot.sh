#!/bin/bash

set -e

if [ "$TRAVIS_BRANCH" == "master" ] ; then
  mvn -DskipTests=true -B --settings share/deploy/travis-settings.xml deploy
  echo "deployed to snapshot release"
else
  echo "this is not master, didn't deploy to snapshot"
fi


