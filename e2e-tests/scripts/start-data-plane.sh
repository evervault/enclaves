#!/bin/sh

export EV_APP_UUID=app_12345678
export CAGE_UUID=cage_123456
export EV_TEAM_UUID=team_12345678
export EV_CAGE_NAME=test-cage


exec $DATA_PLANE_EXECUTABLE_PATH
