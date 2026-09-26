#!/bin/bash
age-keygen -o key.txt
sops --encrypt --age "$(grep public key.txt | cut -d: -f2)" secrets.yaml > secrets.enc.yaml
