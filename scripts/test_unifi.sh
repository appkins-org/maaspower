#!/usr/bin/env bash

# This script is used to test the unifi controller

curl -u test_user:test_pass "http://10.1.0.2:5000/maaspower/rpi1/query"

curl -u test_user:test_pass "http://10.1.0.2:5000/maaspower/rpi1/on"

curl -u test_user:test_pass "http://10.1.0.2:5000/maaspower/rpi1/off"
