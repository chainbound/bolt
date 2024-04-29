#!/bin/bash

echo "Starting the web demo."

# Define the commands as an array
commands=(
    "cd bolt-web-demo/frontend && yarn && yarn dev"
    "cd bolt-web-demo/backend && yarn && yarn dev"
)

# Function to quit all processes on Ctrl+C
quit_all() {
  echo "Caught SIGINT, quitting all processes."
  pids=($(jobs -p))
  for pid in "${pids[@]}"; do
    kill "$pid"  # Ensure to kill each child process
  done
  wait  # Wait for all processes to exit before script exits
  exit
}

# Register the quit_all function to be called on Ctrl+C
trap 'quit_all' SIGINT

# Start the commands in the background
for command in "${commands[@]}"; do
  echo "Starting: $command"
  eval "$command" &  # Use eval to handle complex commands with CD and chaining
done

# Wait for all background processes to finish
wait
