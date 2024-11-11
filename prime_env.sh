#!/bin/bash
#set -x

# defaults
_secret_mount_path="secret"

print_usage() {
    cat <<EOT
Usage: source ${0} [SECRET-MOUNT-PATH] [< FILE]

SECRET-MOUNT-PATH could be used to change secret engine's mount point. Default is: ${_secret_mount_path}

FILE should contain a vault token with properly formatted metadata. When multiple tokens are present, the last one is used.
If FILE is omitted script will read input from stdin. 
EOT
    return 1
}

error() {
    echo "Error: $1" >&2
    return 1
}

command_exists() {
    command -v "$1" &> /dev/null
}

fail_fast() {
    
    if ! command_exists jq; then
        error "jq command not found. Please install."
        return 1
    fi

    if ! command_exists curl; then
        error "curl command not found. Please install."
        return 1
    fi

    # Check args
    if [[ $# -gt 1 ]]; then
        error "Error: Too many arguments."
        print_usage
        return 1
    fi

    # Check if the script is being sourced
    if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
        echo "This script is intended for sourcing only."
        echo "Please use the 'source' command or run as '. $0'"
        print_usage
        return 1
    fi


    # Check if VAULT_ADDR is set and nonempty
    if [[ -z "${VAULT_ADDR}" ]]; then
        error "VAULT_ADDR environment variable is not set."
        return 1
    fi

}


# Checks Vault token and parses its metadata
get_secrets_from_token() {
    local vault_token="$1"

    # Fetch token info
    local curl_result
    curl_result=$(curl -sS \
        --header "X-Vault-Token: ${vault_token}" \
        --request GET \
        "${VAULT_ADDR}/v1/auth/token/lookup-self")

    if [ $? -ne 0 ]; then
        error "The curl command failed."
        return 1
    fi
    
    # Fail if vault returns any error
    local errors
    errors=$(echo "${curl_result}" | jq '.errors')

    if [ "$errors" != "null" ] ; then
        error "Vault token is either invalid or expired."
        return 1
    fi

    # read the list of secrets from token's metadata
    local secrets
    secrets=$(echo "${curl_result}" | jq -r '.data.meta.secrets')

    # Check if list of secrets is present in the response
    if [ -z "$secrets" ] || [ "$secrets" = "null" ]; then
        error "Error: Token's metadata does not contain a list of secrets to fetch."
        return 1
    fi

    echo "$secrets"
}

# Gets a secret from Vault
get_vault_secret() {
    local vault_token="$1"
    local secret="$2"

    # Fetch secret from Vault
    local curl_result
    curl_result=$(curl -sS \
        --header "X-Vault-Token: ${vault_token}" \
        --request GET \
        "${VAULT_ADDR}/v1/${_secret_mount_path}/data/${secret}")

    if [ $? -ne 0 ]; then
        error "The curl command failed."
        return 1
    fi

    # extract 'data'
    local data
    data=$(echo "${curl_result}" | jq -c '.data.data')

    if [ "$data" = "null" ] || [ -z "$data" ]; then
        error "Failed to retrieve '.data.data' field, or it is 'null'."
        return 1
    fi
    
    echo "${data}"
}



# Main script execution
main() {
    
    # Sanity checks
    fail_fast "$@"
    if [ $? -ne 0 ]; then return 1; fi


    # print this when input is from the console
    if [[ -t 0 ]]; then
        echo "Enter vault token" >&2
    fi


    # Check secret engine's mount path argument
    if [[ $# -ge 1 ]]; then
        local arg="$1"

        if [ "$arg" == "--help" ]; then
            print_usage
            return 1
        else
            _secret_mount_path="$arg"
        fi
    fi


    # Read token from stdin
    local vault_token
    local input=$(cat)
    while IFS= read -r line; do
        # Remove '\r' from windows files.
        line=$(echo "$line" | tr -d '\r') 

        vault_token="$line"
    done <<< "$input"

    echo "Priming your environment with secrets..."


    # Read the list of secrets from token's metadata
    local secrets_list
    secrets_list=$(get_secrets_from_token "$vault_token")
    if [ $? -ne 0 ]; then return 1; fi

    # Convert the comma-separated list to a Bash array
    IFS=',' read -r -a secrets_array <<< "$secrets_list"

    # Iterate over the array and fetch contents for each secret path
    local secret_data=()
    for secret in "${secrets_array[@]}"; do
        # Trim whitespaces
        secret=$(echo "$secret" | tr -d '[:space:]')
       
        # Fetch secret data from Vault
        secret_data+=$(get_vault_secret "$vault_token" "$secret")
        if [ $? -ne 0 ]; then return 1; fi
    done

    # Convert the secret_data into array of '{"key":"value"}' pairs
    local kv_pairs=()
    for element in "${secret_data[@]}"; do

        extracted=$(printf '%s' "$element" | jq -c 'to_entries[] | .key as $k | .value as $v | {$k:$v}')
        if [ -n "$extracted" ]; then
            kv_pairs+="$extracted"
        fi
    done

    if [ -z "$kv_pairs" ]; then
        echo "No variables to set"
        return 1
    fi

    # Extract key-value pairs and export them as environment variables
    while IFS= read -r line; do

        key=$(echo "$line" | jq -r 'keys[]')
        value=$(echo "$line" | jq -r --arg key "$key" '.[$key]')

        # alternative for 'export "$key=$value"'
        printf -v "$key" "%s" "$value"
        declare -g -x "$key"
    done < <(echo "$kv_pairs")

    echo "Your env is ready"
}

# Execute the main function
main "$@"






