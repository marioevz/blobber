# Blobber Proposal Actions

## Default

### JSON Name

`default`

### Description

- Sign the block
- Generate the blob sidecars using signed header

Depending on `broadcast_blobs_first` it can:
- Broadcast the blob sidecars
- Broadcast the block

Or:
- Broadcast the block
- Broadcast the blob sidecars

### Parameters

- `broadcast_blobs_first` [bool]: Whether the blobs should be gossiped before the block or not

## Blob Gossip Delay

### JSON Name

`blob_gossip_delay`

### Description

- Sign the block
- Generate the blob sidecars using signed header
- Broadcast the block
- Insert a delay of `delay_milliseconds` milliseconds
- Broadcast the blob sidecars

### Parameters

- `delay_milliseconds` [int]: Amount of milliseconds to delay the blob gossiping


## Equivocating Blob Sidecars

### JSON Name

`equivocating_blob_sidecars`

### Description

- Create an invalid equivocating block by modifying the graffiti
- Sign both blocks
- Generate blob sidecar bundles out of both signed blocks

Depending on `broadcast_blobs_first` it can:
- Broadcast both blob sidecar bundles to different peers
- Broadcast the original signed block only

Or:
- Broadcast the original signed block only
- Broadcast both blob sidecar bundles to different peers

### Parameters

- `broadcast_blobs_first` [bool]: Whether the blobs should be gossiped before the block or not

## Invalid Equivocating Block And Blobs

### JSON Name

`invalid_equivocating_block_and_blobs`

### Description

- Create an invalid equivocating block by modifying the graffiti
- Sign both blocks
- Generate blob sidecars for both blocks

Depending on `broadcast_blobs_first` it can:
- Broadcast the blob sidecars for both blocks to different peers
- Broadcast the signed blocks to different peers

Or:
- Broadcast the signed blocks to different peers
- Broadcast the blob sidecars for both blocks to different peers

### Parameters

- `broadcast_blobs_first` [bool]: Whether the blobs should be gossiped before the block or not
- `alternate_recipients` [bool]: Alternate the recipients of the blocks and blobs every time the action is executed

## Equivocating Block Header In Blobs

### JSON Name

`equivocating_block_header_in_blobs`

### Description

- Create an invalid equivocating block by modifying the graffiti
- Sign both blocks
- Generate the sidecars out of the equivocating signed block only

Depending on `broadcast_blobs_first` it can:
- Broadcast the blob sidecars with the equivocating block header
- Broadcast the original signed block only

Or:
- Broadcast the original signed block only
- Broadcast the blob sidecars with the equivocating block header

### Parameters

- `broadcast_blobs_first` [bool]: Whether the blobs should be gossiped before the block or not

## Invalid Equivocating Block

### JSON Name

`invalid_equivocating_block`

### Description

- Create an invalid equivocating block by modifying the graffiti
- Sign both blocks
- Generate the sidecars out of the correct block only
- Broadcast the blob sidecars
- Broadcast the equivocating signed block and the correct signed block to different peers

### Parameters

None.