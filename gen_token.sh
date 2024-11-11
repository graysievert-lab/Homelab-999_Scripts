#!/bin/bash
#set -x


# defaults
_ttl="10m"

print_usage() {
    cat <<EOT
Usage: ${0} [TTL] [< FILE]

  Issue token with ttl=15m for secrets listed in 'secrets.lst':

      $ ${0} 15m < secrets.lst

TTL specifies the validity period of the generated token. 
Valid suffixes are 'm' for minutes and 'h' for hours. Default: "${_ttl}"
NOTE: Regardless of the provided value, Vault will cap it to 'max_lease_ttl'.

FILE should contain a list of paths to secrets, stripped of the 'secret-mount-path/data/'.
For example, if the full path to a secret is 'secret-mount-path/data/template_project_secrets/some/secret',
it should be written to FILE as 'template_project_secrets/some/secret'.

If FILE is omitted and you run the script without redirection, it will read input from stdin. 
Each path should be on a new line, without the 'secret-mount-path/data/' prefix. 
When you have finished entering all paths, finalize the input by pressing 'Ctrl+D' on an empty line.

Example input format:
template_project_secrets/some/secret
template_project_secrets/another/secret
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

validate_ttl() {
    local ttl="$1"
    local regex='^[0-9]+(m|h)$'
    
    if [[ $ttl =~ $regex ]]; then
        return 0
    else
        return 1
    fi
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

    # Check for TTL argument
    if [[ $# -ge 1 ]]; then
        ttl="$1"
        if ! validate_ttl "$ttl"; then
            error "Error: Invalid TTL format."
            print_usage
            return 1
        fi
        _ttl="$ttl"
    fi

}


convert_path_to_policy_name() {
  local input="$1"
  local output

  # Replace all '/' with '_'
  output="${input//\//_}"
  # Append with '_[read]'
  output="${output}_[read]"

  echo "$output"
}


# Checks Vault environment
get_vault_token() {
    local vault_token

    if [ -z "$VAULT_ADDR" ]; then
        error "VAULT_ADDR environment variable is not set."
        return 1
    fi

    # Try loading token either from environment variable or file
    if [ -n "$VAULT_TOKEN" ]; then
        vault_token="$VAULT_TOKEN"
    elif [ -s "$HOME/.vault-token" ]; then
        vault_token=$(cat "$HOME/.vault-token")
    else
        error "VAULT_TOKEN is not set and $HOME/.vault-token is either empty or does not exist."
        return 1
    fi

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

    echo "$vault_token"
}



# Get the proxmox API token from Vault
create_vault_token() {
    local vault_token="$1"
    local data="$2"

    local curl_result
    curl_result=$(curl -sS \
        --header "X-Vault-Token: ${vault_token}" \
        --request POST \
        --data "$data" \
        "${VAULT_ADDR}/v1/auth/token/create")
    if [ $? -ne 0 ]; then
        error "The curl command failed."
        return 1
    fi

    local token
    token=$(echo "${curl_result}" | jq -r '.auth.client_token')

    if [ "$token" = "null" ] || [ -z "$token" ]; then
        error "Failed to retrieve 'auth.client_token' field, or it is 'null'."
        return 1
    fi
    
    echo "${token}"
}


# Main script execution
main() {
    
    # Sanity checks
    fail_fast "$@"
    if [ $? -ne 0 ]; then return 1; fi

    # Read Vault token from environment
    local vault_token
    vault_token=$(get_vault_token)
    if [ $? -ne 0 ]; then return 1; fi

    # print this when input is from the console
    if [[ -t 0 ]]; then
        echo "Each path should be on a new line, without the 'secret-mount-path/data/' prefix." >&2
        echo "Finalize the input by pressing 'Ctrl+D' on an empty line." >&2
    fi

    # Populate policies and secrets arrays from stdin
    local policies_array=("lookup-self")
    local secrets_array=()

    local input=$(cat)
    while IFS= read -r line; do
        # Remove '\r' from windows files.
        line=$(echo "$line" | tr -d '\r') 
        
        policies_array+=("$(convert_path_to_policy_name "$line")")
        secrets_array+=("$line")
    done <<< "$input"

    # Flatten array into string with comma as separator
    secrets=$(IFS=,; echo "${secrets_array[*]}")

    # Flatten array into string with newline as separator
    policies=$(IFS=$'\n'; echo "${policies_array[*]}")
    # Then convert into JSON array
    json_policies=$(echo "$policies" | jq -R . | jq -s .)

    # Prepare payload
    data=$(jq -n \
            --argjson policies "$json_policies" \
            --arg secrets "$secrets" \
            --arg ttl "$_ttl" \
            '{
            policies: $policies,
            meta: { 
                secrets: $secrets 
                },
            no_parent: true,
            no_default_policy: true,
            renewable: false,
            ttl: $ttl,
            type: "batch"
            }'
        )

    # Create vault token to access requested secrets
    local access_token
    access_token=$(create_vault_token "$vault_token" "$data")
    if [ $? -ne 0 ]; then return 1; fi
    
    echo "$access_token"
}

# Execute the main function
main "$@"
