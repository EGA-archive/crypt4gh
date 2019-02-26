#!/bin/bash

alias="crypt4gh"

if ! which jq > /dev/null; then
    echo "This script needs jq. Please install and try again."
    exit 1
fi

if ! which aws > /dev/null; then
    echo "This script needs aws-cli. Please install and try again."
    exit 1
fi


set -e

key_arn=$(aws kms create-key | jq -r .KeyMetadata.Arn)
aws kms create-alias --alias-name alias/${alias} --target-key-id $key_arn
echo "Successfully created key $key_arn with alias $alias"