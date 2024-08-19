* If a customer has a health-check endpoint configured for their Enclave and it returns a bad response to the data plane, the data plane should pass the response payload to the host process to be included in the logs

* The default health-check should account for the internal functions of the data plane, beyond the data plane state. This should track if: E3 calls health, DNS lookups health, Attestation health

* The data plane state when starting up should walk through its states (attesting, loading env, [obtaining TLS cert] starting user process, running)
