#!/bin/sh
socat TCP-LISTEN:13337,REUSEADDR,FORK EXEC:"./oneshot"
