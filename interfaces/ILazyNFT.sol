//SPDX-License-Identifier: MIT
pragma solidity =0.8.13;

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
// import {NFTVoucher} from "../contracts/LazyNFT.sol";

/// @notice Represents an un-minted NFT, which has not yet been recorded into the blockchain. A signed voucher can be redeemed for a real NFT using the redeem function.
struct NFTVoucher {
    /// @notice The id of the token to be redeemed. Must be unique - if another token with this ID already exists, the redeem function will revert.
    uint256 tokenId;
    /// @notice The minimum price (in wei) that the NFT creator is willing to accept for the initial sale of this NFT.
    uint256 minPrice;
    /// @notice The metadata URI to associate with this token.
    string uri;
    /// @notice the EIP-712 signature of all other fields in the NFTVoucher struct. For a voucher to be valid, it must be signed by an account with the MINTER_ROLE.
    bytes signature;
}

interface ILazyNFT is IERC721 {
    function redeem(address redeemer, NFTVoucher calldata voucher)
        external
        payable
        returns (uint256);

    function nonLazyMint(address to, string memory _uri)
        external
        payable
        returns (uint256);
}
