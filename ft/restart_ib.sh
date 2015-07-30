#!/usr/bin/env bash

service network stop
service opensmd stop
service openibd start
service opensmd start
service network start
