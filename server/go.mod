module netsecProject/server

go 1.13


require (
    netsecProject/utils/DH/dh v0.0.0
)

replace (
    netsecProject/utils/DH/dh => ../utils/DH
)
