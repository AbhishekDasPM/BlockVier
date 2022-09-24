//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;
//pragma abicoder v2; // required to accept structs as function parameters
import "../interfaces/ILazyNFT.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

// /// @notice Represents an un-minted NFT, which has not yet been recorded into the blockchain. A signed voucher can be redeemed for a real NFT using the redeem function.
// struct NFTVoucher {
//     /// @notice The id of the token to be redeemed. Must be unique - if another token with this ID already exists, the redeem function will revert.
//     uint256 tokenId;
//     /// @notice The minimum price (in wei) that the NFT creator is willing to accept for the initial sale of this NFT.
//     uint256 minPrice;
//     /// @notice The metadata URI to associate with this token.
//     string uri;
//     /// @notice the EIP-712 signature of all other fields in the NFTVoucher struct. For a voucher to be valid, it must be signed by an account with the MINTER_ROLE.
//     bytes signature;
// }

contract LazyNFTv1 is
    ILazyNFT,
    ERC721URIStorage,
    EIP712,
    AccessControl,
    Pausable
{
    /**n @dev =========================================================== State Variables ============================================================= */

    using Counters for Counters.Counter;
    Counters.Counter private _tokenIdCounter;

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    string private constant SIGNING_DOMAIN = "LazyNFT-Voucher";
    string private constant SIGNATURE_VERSION = "1";

    address public MarketAddress;
    uint256 public listingFee;

    mapping(address => uint256) public pendingWithdrawals;
    event EtherReceived(address indexed sender, uint256 indexed value);

    error ZeroAddress(address redeemer);

    /**n @dev ============================================================ State Variables Ends ============================================================= */

    /**@notice =============================================================== Constructor ================================================================== */

    constructor(address payable minter)
        ERC721("LazyNFT", "LAZ")
        EIP712(SIGNING_DOMAIN, SIGNATURE_VERSION)
    {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, minter);

        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
    }

    /**@notice =============================================================== Constructor Ends ================================================================= */

    /**@notice ========================================================== State Modifiying Funcitions =========================================================== */

    /** @dev SETS MARKET-PLACE ADDRESS TO BE APPROVED FOR NFT TRANSFER BY THE NFT OWNER */

    function setMarketPlaceAddress(address _marketPlaceAddress) external {
        require(isContract(_marketPlaceAddress), "invalid address.");

        MarketAddress = _marketPlaceAddress;
    }

    function setListingFee(uint256 _listingFee) external {
        listingFee = _listingFee;
    }

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /// @notice Redeems an NFTVoucher for an actual NFT, creating it in the process.
    /// @param redeemer The address of the account which will receive the NFT upon success.
    /// @param voucher A signed NFTVoucher that describes the NFT to be redeemed.
    function redeem(address redeemer, NFTVoucher calldata voucher)
        public
        payable
        override
        returns (uint256)
    {
        if (redeemer == address(0)) {
            revert ZeroAddress(redeemer);
        }


        // make sure signature is valid and get the address of the signer
        address signer = _verify(voucher);

        // make sure that the signer is authorized to mint NFTs
        require(
            hasRole(MINTER_ROLE, signer),
            "Signature invalid or unauthorized"
        );

        // make sure that the redeemer is paying enough to cover the buyer's cost
        require(msg.value >= voucher.minPrice, "Insufficient funds to redeem");

        /// @dev first assign the token to the signer, to establish provenance on-chain

        _mint(signer, voucher.tokenId);
        _setTokenURI(voucher.tokenId, voucher.uri);

        // transfer the token to the redeemer
        _transfer(signer, redeemer, voucher.tokenId);

        _setApprovalForAll(redeemer, address(this), true);

        require(isApprovedForAll(redeemer, address(this)));

        // record payment to signer's withdrawal balance
        pendingWithdrawals[signer] += msg.value;

        emit EtherReceived(redeemer, msg.value);

        return voucher.tokenId;
    }

    function nonLazyMint(address to, string memory _uri)
        public
        payable
        returns (uint256)
    {
        require(msg.value >= listingFee, "Send Listing fee in Eth.");
        require(_msgSender() != address(0));
        // require(msg.value >= listingFee); // listing fee in Eth

        unchecked {
            _tokenIdCounter.increment();
        }

        uint256 newTokenId = _tokenIdCounter.current();

        _safeMint(to, newTokenId);

        _setTokenURI(newTokenId, _uri);
        // _setApprovalForAll(to, MARKETADDRESS, true);

        _approve(MarketAddress, newTokenId);

        require(_isApprovedOrOwner(MarketAddress, newTokenId));

        // require(isApprovedForAll(to, MARKETADDRESS));

        /// OR NEED TO TEST BOTH APPROVE AND BELOW FUNCTION AND DECIDE WHICH ONE TO KEEP

        // _safeTransfer(msg.sender, address(this), newTokenId, "");

        ///uint256 newTokenId = safeMint(msg.sender, _uri);

        // _transfer(to, MarketAddress, newTokenId);

        emit EtherReceived(_msgSender(), msg.value);

        return (newTokenId);
    }

    /** @dev  Transfers all pending withdrawal balance to the AUTHORIZED caller. Reverts if not AUTHORIZED. */

    function withdraw() public {
        require(
            hasRole(MINTER_ROLE, _msgSender()),
            "Only authorized minters can withdraw"
        );

        // IMPORTANT: casting msg.sender to a payable address is only safe if ALL members of the minter role are payable addresses.
        address payable receiver = payable(_msgSender());

        uint256 amount = pendingWithdrawals[receiver];
        // zero account before transfer to prevent re-entrancy attack
        pendingWithdrawals[receiver] = 0;
        receiver.transfer(amount);
    }

    /**@notice =========================================================== State Modifiying Funcitions Ends ======================================================== */

    /**@notice ================================================================= View Funcitions ==================================================================== */

    /// @notice Retuns the amount of Ether available to the caller to withdraw.
    function availableToWithdraw() public view returns (uint256) {
        return pendingWithdrawals[_msgSender()];
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(AccessControl, ERC721, IERC165)
        returns (bool)
    {
        return
            ERC721.supportsInterface(interfaceId) ||
            AccessControl.supportsInterface(interfaceId);
    }

    /// @notice Returns the chain id of the current blockchain.
    /// @dev This is used to workaround an issue with ganache returning different values from the on-chain chainid() function and
    ///  the eth_chainId RPC method. See https://github.com/protocol/nft-website/issues/121 for context.

    function getChainID() external view returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }

    receive() external payable {
        require(_msgSender() != address(0));
        emit EtherReceived(_msgSender(), msg.value);
    }

    /**@notice =========================================================== Internal and Private Funcitions =========================================================== */

    /// @notice Returns a hash of the given NFTVoucher, prepared using EIP712 typed data hashing rules.
    /// @param voucher An NFTVoucher to hash.
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
                        voucher.tokenId,
                        voucher.minPrice,
                        keccak256(bytes(voucher.uri))
                    )
                )
            );
    }

    /// @notice Verifies the signature for a given NFTVoucher, returning the address of the signer.
    /// @dev Will revert if the signature is invalid. Does not verify that the signer is authorized to mint NFTs.
    /// @param voucher An NFTVoucher describing an unminted NFT.
    function _verify(NFTVoucher calldata voucher)
        internal
        view
        returns (address)
    {
        bytes32 digest = _hash(voucher);
        return ECDSA.recover(digest, voucher.signature);
    }

    /**
     * Check if a specific address is
     * a contract address
     * @param _addr: address to verify
     */
    function isContract(address _addr) private view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
    }

    /**@notice =========================================================== Internal and Private Funcitions Ends =========================================================== */
}
