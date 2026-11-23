Owners: core-engineer, connector-engineer, qa

Add Azure and Alibaba Cloud blast-radius mappers (#848, epic #817): Entra service-principal secrets map Graph app roles, directory roles, and per-subscription ARM role assignments (Owner/Contributor/User Access Administrator and privileged Graph or directory roles flag the map); storage-account shared keys list blob containers with SharedKey signing; Alibaba AccessKeys resolve STS caller identity and RAM user policies. Detector context (`tenant_id`, `client_id`, `account`, `api_endpoint`) now flows into `AccessCredential.Extra`.
