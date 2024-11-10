#!/bin/sh
socat TCP-LISTEN:6969,REUSEADDR,FORK EXEC:"./jitinator"
