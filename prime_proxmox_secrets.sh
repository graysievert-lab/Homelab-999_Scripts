#!/bin/bash
#set -x

# Constants. Adjust in accordance with your vault configuration
_sshca_path="ssh-iac-usercert"
_sshca_role="iac"

_proxmox_path="proxmox-tokens"
_proxmox_role="apitoken"

_pvetoken_var="TF_VAR_pvetoken"


print_usage() {
    echo "Usage: source ${BASH_SOURCE[0]} key.pub"
    echo "  Signed public ssh key will be written to key-cert.pub and loaded to ssh-agent"
    echo "  Variable ${_pvetoken_var} will be set with the formatted Proxmox token"
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
    
    if ! command_exists ssh-add; then
        error "ssh-add command not found. Make sure the SSH agent is running."
        return 1
    fi

    if ! command_exists jq; then
        error "jq command not found. Please install."
        return 1
    fi

    if ! command_exists curl; then
        error "curl command not found. Please install."
        return 1
    fi


    # check args
    if [ "${#}" -ne 1 ]; then
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
}


select_public_key(){
    local key_file="$1"

    # ensure that input file has .pub extension
    local public_key
    if [[ "${key_file%.pub}" == "${key_file}" ]]; then
        public_key="${key_file}.pub"
    else
        public_key="${key_file}"
    fi
    
    echo "$public_key"
}

load_public_key(){
    local public_key="$1"

    local public_key_content
    if [ ! -s "$public_key" ]; then
        error "Public key file does not exist or empty: $public_key"
        return 1
    else
        public_key_content=$(cat "$public_key")    
    fi

    echo "$public_key_content"
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


add_key_to_ssh_agent() {

    local public_key="$1"

    # Strip .pub extension
    local private_key="${public_key%.pub}"
    if [ ! -f "$private_key" ]; then
        error "Private key file is not found. Cant use ssh-add."
        return 1
    fi

    ssh-add "$private_key"

    if [ $? -ne 0 ]; then
        error "Failed to add key to SSH agent."
        return 1
    else
        echo "Key added to SSH agent successfully."
    fi
    
}

# Get the signed key from Vault
get_signed_key() {
    local public_key_content="$1"
    local vault_token="$2"
    
    local curl_result
    curl_result=$(curl -Ss \
        --header "X-Vault-Token: ${vault_token}" \
        --request POST \
        --data "{\"public_key\": \"${public_key_content}\"}" \
        "${VAULT_ADDR}/v1/${_sshca_path}/sign/${_sshca_role}")

    if [ $? -ne 0 ]; then
        error "The curl command failed."
        return 1
    fi

    signed_key=$(echo "${curl_result}" | jq -r '.data.signed_key')

    if [ "$signed_key" = "null" ] || [ -z "$signed_key" ]; then
        error "Failed to retrieve the signed key or the key is null."
        return 1
    fi

    echo "$signed_key"
}

# Function to determine the output file path and write the signed key to it
write_signed_key_to_file() {
    local signed_key="$1"
    local public_key_path="$2"

    # Determine the output file path by appending '-cert' before the file extension
    local output_file="${public_key_path%.pub}-cert.pub"

    echo "$signed_key" > "$output_file" 

    if [ $? -ne 0 ]; then
        error "Failed to write signed key to $output_file."
        return 1
    else 
        echo "Signed key saved to $output_file"
    fi      
}

# Get the proxmox API token from Vault
get_proxmox_token() {
    local vault_token="$1"

    local curl_result
    curl_result=$(curl -Ss \
        --header "X-Vault-Token: ${vault_token}" \
        --request GET \
        "${VAULT_ADDR}/v1/${_proxmox_path}/creds/${_proxmox_role}")

    if [ $? -ne 0 ]; then
        error "The curl command failed."
        return 1
    fi

    local token_id_full
    token_id_full=$(echo "${curl_result}" | jq -r '.data.token_id_full')

    if [ "$token_id_full" = "null" ] || [ -z "$token_id_full" ]; then
        error "Failed to retrieve 'token_id_full' field, or it is 'null'."
        return 1
    fi

    local secret
    secret=$(echo "${curl_result}" | jq -r '.data.secret')

    if [ "$secret" = "null" ] || [ -z "$secret" ]; then
        error "Failed to retrieve 'secret' field, or it is 'null'."
        return 1
    fi
    
    echo "${token_id_full}=${secret}"
}


# Main script execution
main() {
    
    # Sanity checks
    fail_fast "$@"
    if [ $? -ne 0 ]; then return 1; fi

    # Ensure correct key file is loaded
    local public_key
    public_key=$(select_public_key "$1")
    if [ $? -ne 0 ]; then return 1; fi

    # Read public key 
    local public_key_content
    public_key_content=$(load_public_key "$public_key") 
    if [ $? -ne 0 ]; then return 1; fi

    # Fetch Vault token
    local vault_token
    vault_token=$(get_vault_token)
    if [ $? -ne 0 ]; then return 1; fi

    # Get signed ssh key from vault
    local signed_key
    signed_key=$(get_signed_key "$public_key_content" "$vault_token")
    if [ $? -ne 0 ]; then return 1; fi

    # Write the signed public key to -cert file
    write_signed_key_to_file "$signed_key" "$public_key"
    if [ $? -ne 0 ]; then return 1; fi

    # Add private key and certificate to ssh-agent
    add_key_to_ssh_agent "$public_key"
    if [ $? -ne 0 ]; then return 1; fi

    # Get Proxmox token API token from vault
    local proxmox_token
    proxmox_token=$(get_proxmox_token "$vault_token")
    if [ $? -ne 0 ]; then return 1; fi

    # And set it to a shell variable
    printf -v "$_pvetoken_var" "%s" "$proxmox_token"
    declare -g -x "$_pvetoken_var"

    echo "${_pvetoken_var} has been set."
}

# Execute the main function
main "$@"
