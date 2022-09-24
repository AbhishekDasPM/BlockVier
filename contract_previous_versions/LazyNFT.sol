//SPDX-License-Identifier: MIT
pragma solidity =0.8.13;
//pragma abicoder v2; // required to accept structs as function parameters

// import "./AbstractBaseNFT.sol";

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

/// @notice Represents an un-minted NFT, which has not yet been recorded into the blockchain.
///A signed voucher can be redeemed for a real NFT using the redeem function.

struct NFTVoucher {
    /// @notice The unique id of the token to be redeemed otherwise reverts.
    uint256 voucherId;
    /// @notice The minimum price (in wei) by the NFT creator.
    uint256 minPrice;
    uint256 buyNowPrice;
    /// @notice The metadata URI to associate with this token.
    string uri;
    address creator;
    IERC20 paymentToken;
    /// @notice the EIP-712 signature of all other fields in the NFTVoucher struct.
    /// @dev For a voucher to be valid, it must be signed by an account with the MINTER_ROLE.

    bytes signature;
}

contract LazyNFT is
    ERC721,
    ERC721Enumerable,
    ERC721URIStorage,
    Pausable,
    AccessControl,
    ReentrancyGuard,
    EIP712
{
    using SafeERC20 for IERC20;

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    string private constant SIGNING_DOMAIN_NAME = "LazyNFT-Voucher";
    string private constant SIGNING_DOMAIN_VERSION = "1";

    using Counters for Counters.Counter;
    Counters.Counter private _tokenIdCounter;

    // uint256 public listingFee; // LISTING FEE IN ETH

    // address public immutable MARKETADDRESS;

    constructor(address payable minter)
        ERC721("LazyNFT", "LAZ")
        EIP712(SIGNING_DOMAIN_NAME, SIGNING_DOMAIN_VERSION)
    {
        // need to ADD  require statement to check for provider _marketaddress is a contract address with code and not EOA using EXTCODE ASSEMBLY
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _setupRole(MINTER_ROLE, minter);

        // require(isContract(_marketAddress));

        // MARKETADDRESS = _marketAddress;
    }

    /**
     * Check if a specific address is
     * a contract address
     * @param _addr: address to verify
     */
    // function isContract(address _addr) private view returns (bool) {
    //     uint256 size;
    //     assembly {
    //         size := extcodesize(_addr)
    //     }
    //     return size > 0;
    // }

    /// @dev stores all the off chain NFT signed vouchers to keep track of
    // NFTVoucher[] public signedVouchers;

    /// @dev to keep track of all the off chain NFT signed vouchers via an unique id
    // mapping(uint256 => NFTVoucher) public voucherIdToNFTVoucher;

    struct PaymentToken {
        IERC20 paymentToken;
        uint256 value;
    }

    // function storeNFTVouchers(NFTVoucher calldata voucher) public {
    //     signedVouchers.push(voucher);
    // }

    /// @notice Redeems an NFTVoucher for an actual NFT, creating it in the process.
    /// @param redeemer The address of the account which will receive the NFT upon success.
    /// @param voucher A signed NFTVoucher that describes the NFT to be redeemed.

    function redeem(
        address redeemer,
        NFTVoucher calldata voucher
         
    ) public payable nonReentrant returns (uint256) {

        address signer = _verify(voucher);
        // make sure that the signer is authorized to mint NFTs
        require(
            hasRole(MINTER_ROLE, signer),
            "Signature invalid or unauthorized"
        );

        

        unchecked {
            _tokenIdCounter.increment();
        }

        uint256 newTokenId = _tokenIdCounter.current();

        // first assign the token to the signer, to establish provenance on-chain
        _safeMint(signer, newTokenId);
        _setTokenURI(newTokenId, voucher.uri);

        // transfer the token to the redeemer
        _transfer(signer, redeemer, newTokenId);
        //0xf8e81D47203A594245E36C48e151709F0C19fBe8
        // record payment to signer's withdrawal balance

        _setApprovalForAll(redeemer, address(this), true);

        require(isApprovedForAll(redeemer, address(this)));

        return newTokenId;
    }

    function getChainID() external view returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }

    function _verify(NFTVoucher calldata voucher)
        internal
        view
        returns (address)
    {
        bytes32 digest = _hash(voucher);
        return ECDSA.recover(digest, voucher.signature);
    }

    function _hash(NFTVoucher calldata voucher)
        internal
        view
        returns (bytes32)
    {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        keccak256(
                            "NFTVoucher(uint256 tokenId,uint256 minPrice,string uri)"
                        ),
                        voucher.voucherId,
                        voucher.minPrice,
                        keccak256(bytes(voucher.uri))
                    )
                )
            );
    }

    /// @notice Mint nft onchain without Lazymint and list on the  market

    // function nonLazyMint(address to, string memory _uri)
    //     public
    //     payable
    //     returns (uint256)
    // {
    //     require(_msgSender() != address(0));
    //     // require(msg.value >= listingFee); // listing fee in Eth

    //     unchecked {
    //         _tokenIdCounter.increment();
    //     }

    //     uint256 newTokenId = _tokenIdCounter.current();

    //     _safeMint(to, newTokenId);

    //     _setTokenURI(newTokenId, _uri);
    //     // _setApprovalForAll(to, MARKETADDRESS, true);

    //     _approve(MARKETADDRESS, newTokenId);

    //     _isApprovedOrOwner(MARKETADDRESS, newTokenId);

    //     // require(isApprovedForAll(to, MARKETADDRESS));

    //     /// OR NEED TO TEST BOTH APPROVE AND BELOW FUNCTION AND DECIDE WHICH ONE TO KEEP

    //     // _safeTransfer(msg.sender, address(this), newTokenId, "");

    //     ///uint256 newTokenId = safeMint(msg.sender, _uri);

    //     _transfer(to, to, newTokenId);

    //     return (newTokenId);
    // }

    // to withdraw any eth sent to it. Only callable by PAUSER_ROLE;

    function withdraw(address _ethReceiver) external onlyRole(PAUSER_ROLE) {
        payable(_ethReceiver).transfer(balanceOf(address(this)));
    }

    /** -------------------------------------------- @dev Other ERC721 implementaions------------------------------------------------------*/

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal override(ERC721, ERC721Enumerable) whenNotPaused {
        super._beforeTokenTransfer(from, to, tokenId);
    }

    // The following functions are overrides required by Solidity.//

    function _burn(uint256 tokenId)
        internal
        override(ERC721, ERC721URIStorage)
        onlyRole(MINTER_ROLE)
    {
        super._burn(tokenId);
    }

    function tokenURI(uint256 tokenId)
        public
        view
        override(ERC721, ERC721URIStorage)
        returns (string memory)
    {
        return super.tokenURI(tokenId);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, ERC721Enumerable, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    /** ----------------------------------------------------- @dev ERC721 implementation ends here------------------------------------------- */
}
