# Beacon Chain DevP2P Blob Testing Proxy

<img src="blobber_logo.png" width="200" height="200">


Testing tool that sits as a proxy between the beacon and validator clients in order to intercept proposals, and then modify, delay, conceal or corrupt the blobs included in the proposal, which are then relayed to all the beacon clients via the DevP2P network.

```mermaid
    graph LR;
        subgraph identifier[" "]
            beaconClient(Beacon Client)
            validatorClient(Validator Client)
            proxy(Blobber)
            BeaconDevP2P(Beacon DevP2P Network)
        end

        validatorClient -->|Attestations Request| proxy
        proxy -->|Attestations Request| beaconClient
        beaconClient -->|Attestations Response| proxy
        proxy -->|Attestations Response| validatorClient

        validatorClient -->|Proposal Request| proxy
        proxy -->|Proposal Request| beaconClient
        beaconClient -->|Proposal Response| proxy
        proxy -.->|Modified/Signed Proposal Response| BeaconDevP2P

        linkStyle 0,1 stroke-width:3px,fill:none,stroke:darkgreen;
        linkStyle 2,3 stroke-width:3px,fill:none,stroke:green;
        linkStyle 4,5 stroke-width:3px,fill:none,stroke:blue;
        linkStyle 6,7 stroke-width:3px,fill:none,stroke:darkblue;

```