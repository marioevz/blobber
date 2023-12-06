# Beacon Chain DevP2P Blob Testing Proxy

<img src="blobber_logo.png" width="200" height="200">

## !! WARNING !!

Running some of the actions included in this tool will get a validator **SLASHED**.

Please exercise caution when using this tool and never use it on Mainnet!

## Description

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

## Installation

```bash
git clone https://github.com/marioevz/blobber.git
cd blobber
go build -o blobber ./cmd
./blobber --help
```

## Use with Docker

```bash
docker run -it ethpandaops/blobber:latest --help
```

## Configuration

The blobber requires at least one consensus client in Beacon Node + Validator Client configuration, and the `--cl` flag must be provided to point to the Beacon Node REST API endpoint:

```bash
--cl http://beacon_node_1:4000/ --cl http://beacon_node_2:4000/ ...
```

The Beacon Node endpoint will be used to relay all Validator Client requests and intercept proposals, and also to obtain the client's ENR, which the blobber will use to connect to the client via devp2p.

The validator client must be then configured to connect to the blobber instead of the Beacon Node, starting at port 20,000 (by default) and increasing by 1 for each Beacon Node configured using the `--cl` flag.

## Proposal Actions

The blobber can be configured to perform actions on a block proposal, such as delaying blobs broadcasting, create equivocating blob sidecars, among other things.

At the moment, the blobber can be configured to do one proposal action with a certain frequency.

To configure the proposal action the flag `--proposal-action` is used:

```bash
--proposal-action '{"name": "blob_gossip_delay"}'
```

Each proposal action has configurable parameters which can be set with the same flag:

```bash
--proposal-action '{"name": "blob_gossip_delay", "delay_milliseconds": 1000}'
```

To see a list of available proposal actions see [here](./proposal_actions/README.md).