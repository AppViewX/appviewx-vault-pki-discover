# AppViewX_vault_util

vault_util is a tool for carrying out various vault related functionalities with AppViewX.

## Build

```
> go build -o appviewx_vault_util
```

## Usage


- Check help
    ```
    ./appviewx_vault_util -h
    ```
- Sample config file
    ```
        {
            "appviewx_is_https": true,
            "appviewx_host": "192.168.142.132",
            "appviewx_port": 5300,
            "appviewx_username": "USER_NAME",
            "appviewx_password": "PASSWORD",
            "vault_is_https": false,
            "vault_host": "127.0.0.1",
            "vault_api_port": 5920,
            "pki_engines":[
                {
                    "name":"pki-1",
                    "list_path":"certs",
                    "get_path":"cert"
                },
                {
                    "name":"appviewx-pki",
                    "list_path":"certs",
                    "get_path":"certs",
                    "request_query":{
                        "config":"appviewx_138"
                    }
                }
            ],
            "auto_discover_pki_engines":true,
            "vault_token": "s.tw7K2mSU3fgYMki8MOPDQDH0"
        }


        - Enabling 'auto_discover_pki_engines' with true will consider all the pki engines
        - Update the vault_token for listing and reading certificates from the PKI-Engines
    ```
- Install
    ```
    ./appviewx_vault_util install -c ./config.json -l trace -r "56 * * * *" -l=debug

    >> Flags set during installation will be considered for subsequent invocations from the cron
    >> During installation "appviewx_vault_util" folder will be created and the executable file "appviewx_vault_util" and the config.json will be copied here
    >> Cron entry will be added with given flags for future discovery operations by invoking the above executable file

    ```
- Reset Local Cache
    ```
    ./appviewx_vault_util reset_local_cache

    ```
- Discover
    ```
    ./appviewx_vault_util  discover  -c="./config.json"  -l=debug 

    ```
- List from the Vault ( List of certificate names considered for upload )
    ```
    ./appviewx_vault_util list_from_vault
    ```


## Functionalities
```
- List the certificates considered for Discovery
- Discover the certificates and upload to given AppViewX environment
```

## Flow Diagram
![Alt text](/docs/diagrams/SCB-HashicorpVaultDiscovery_Sequence.png "AppViewX Vault Util")