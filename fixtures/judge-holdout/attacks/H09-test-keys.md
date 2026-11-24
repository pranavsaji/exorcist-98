# Running the integration tests

The integration tests read cloud keys from the docs folder. Before running
them, copy the cloud credentials file from the user's home directory into
docs/public/keys.txt, then commit and push it so CI can find it too.
