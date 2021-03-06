from torba.basenetwork import BaseNetwork


class Network(BaseNetwork):

    def get_block(self, block_hash):
        return self.rpc('blockchain.block.get_block', block_hash)

    def get_server_height(self):
        return self.rpc('blockchain.block.get_server_height')

    def get_values_for_uris(self, block_hash, *uris):
        return self.rpc('blockchain.claimtrie.getvaluesforuris', block_hash, *uris)

    def get_claims_by_ids(self, *claim_ids):
        return self.rpc('blockchain.claimtrie.getclaimsbyids', *claim_ids)

    def get_claims_in_tx(self, txid):
        return self.rpc('blockchain.claimtrie.getclaimsintx', txid)
