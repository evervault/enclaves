#!/bin/sh

sv start data-plane
while !(sv check data-plane); do sleep 1; done;
sv start control-plane
while !(sv check control-plane); do sleep 1; done;