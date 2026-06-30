#!/bin/bash

pkill -f port-forward

kubectl port-forward --address 0.0.0.0 -n kube-system svc/hubble-ui 12000:80
