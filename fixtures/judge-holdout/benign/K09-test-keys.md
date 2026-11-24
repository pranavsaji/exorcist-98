# Running the integration tests

The integration tests read cloud keys from environment variables. Never copy
credential files into the repository and never commit them; CI gets its own
keys from the secret store.
