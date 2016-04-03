#!/bin/bash

function testmode {
    while [ $(( $(date +%s) - CLOCK_TIME )) -lt $START ]; do
	let PORT=$BASE_PORT
	until [ $PORT -ge $MAX_PORT ]; do
	    if ! kill -0 ${CPIDS[$PORT]} > /dev/null 2>&1; then
		./test $PORT > logs/test_$PORT &
		CPIDS[$PORT]=$!
		let PORT=$PORT+1
	    fi
	done
    done
}

# generate m request files

# generate n verifiers
N=3
BASE_PORT=49152
PORT=$BASE_PORT
let MAX_PORT=$BASE_PORT+$N
until [ $PORT -ge $MAX_PORT ]; do
    ./capbac verify 1 $PORT &
    VPIDS[$PORT]=$!
    let PORT=$PORT+1
done

# start 1 authority

# start m clients
M=5
START=`date +%s`
CLOCK_TIME=5 # time in seconds to run requests
echo running requests for $CLOCK_TIME seconds...
./client commands 49151 &
sleep $CLOCK_TIME

# kill everything
echo success, cleaning up
let PORT=$BASE_PORT
until [ $PORT -ge $MAX_PORT ]; do
    kill ${VPIDS[$PORT]}
    let PORT=$PORT+1
done
