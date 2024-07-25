#!/bin/sh

# Check if the remotebeast context already exists on the system
context_exists=$(docker context ls --format '{{.Name}}' | grep -c '^remotebeast$')
if [ "$context_exists" -eq 0 ]; then
  if docker context create remotebeast --docker "host=ssh://shared@remotebeast"; then
    echo "Successfully created the remotebeast context"
  else
    echo "Failed to create the remotebeast context"
  fi
else
  echo "The remotebeast context already exists"
fi
