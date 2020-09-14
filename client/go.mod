module netsecProject/client

go 1.13


require (
    netsecProject/utils/DH/dh v0.0.0
    netsecProject/utils/AES/aesUtils v0.0.0
)

replace (
    netsecProject/utils/DH/dh => ../utils/DH
    netsecProject/utils/AES/aesUtils => ../utils/AES
)