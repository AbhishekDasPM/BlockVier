//SPDX-License-Identifier: MIT
pragma solidity =0.8.13;

pragma abicoder v2; // required to accept structs as function parameters

/// @dev THIS CONTRACT IS FOR ONLY BIDS ON LAZYMINT VOUCHER...THERE IS NOT NON-LAZYMINT ACTIVITY HERE STRICTLY....///

// import "./AbstractBaseNFT.sol";

// import "./LazyNFT.sol";

interface ILazyNFT is IERC721 {
    function redeem(address redeemer, NFTVoucher calldata voucher)
        external
        returns (uint256);
}
import {NFTVoucher} from "../contracts/LazyNFT.sol";

import "../interfaces/ILazymintMarket.sol";

// import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
// import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";

// import "@openzeppelin/contracts/utils/Counters.sol";

contract MarketV2 is
    ILazymintMarket,
    Pausable,
    AccessControl,
    ERC721Holder,
    ReentrancyGuard,
    EIP712
{
    // using SafeERC20 for IERC20;

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    string private constant SIGNING_DOMAIN_NAME = "LazyNFT-Voucher";
    string private constant SIGNING_DOMAIN_VERSION = "1";

    ILazyNFT public nftContract;

    // using Counters for Counters.Counter;
    // Counters.Counter private _tokenIdCounter;

    uint256 public listingFee; // LISTING FEE IN ETH

    // struct NFTVoucher {
    //     uint256 tokenId;
    //     uint256 minPrice;
    //     string uri;
    //     address creator;
    //     IERC20 paymentToken;
    //     Bid bids;
    //     /// @notice the EIP-712 signature of all other fields in the NFTVoucher struct.
    //     /// @dev For a voucher to be valid, it must be signed by an account with the MINTER_ROLE.

    //     bytes signature;
    // }

    // MarketItem[] public marketItems;
    // Bid[] public bids;
    // NFTVoucher[] public signedVouchers;

    // keep track of all eth sent by each bidders.
    // mapping(address => uint256) public pendingWithdrawalsBidder;
    // or
    mapping(address => Drawable) drawablesBidder;

    // keep track of eth to be withdrawn by each seller;
    // mapping(address => uint256) public pendingWithdrawalSeller;
    //or
    mapping(address => Drawable) drawableSeller;

    //keep track of all ERC20 sent by each bidder.
    mapping(address => uint256) pendingERC20Withdrawals;

    // keeps track of bidder to erc20 token address to amount bid
    mapping(address => mapping(address => uint256))
        public pendingWithdrawalsERC20;

    // mapping(address => mapping(uint256 => MarketItem)) public nftToMarketItem;
    // mapping(uint256 => NFTVoucher) public tokenIdToNFTVoucher;

    mapping(uint256 => address) public tokenIdToNFTcontract;

    // mapping(uint256 => MarketItem) public tokenIdToMarketItem;

    // to keep track of bids made on each on-chain minted nft til now
    // mapping(uint256 => MarketItem) public tokenIdToBids;

    // to keep track of bids made on each voucher
    // mapping(uint256 => MarketItem) public voucherIdToBids;

    mapping(uint256 => Bid) voucherToBids;

    /** @notice -------------------------------------------------------CONSTRUCTOR---------------------------------------------------------------- */

    constructor(address _nftContract)
        EIP712(SIGNING_DOMAIN_NAME, SIGNING_DOMAIN_VERSION)
    {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);

        require(isContract(_nftContract));

        nftContract = ILazyNFT(_nftContract);
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

    /** @notice ---------------------------------------------------- ERC721 Access control----------------------------------------------------------- */

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /** @notice ---------------------------------------------------- ERC721 Access control Ends here--------------------------------------------------- */

    /** @notice --------------------------------------------------NFT VOUCHER RELATED FUNCTIONS START HERE---------------------------------------------- */

    /// @notice Function to buy now nft

    function buyNFTVoucherNowWithEth(
        address redeemer,
        NFTVoucher calldata voucher,
        uint256 _voucherId
    ) public payable returns (uint256) {
        // to ensure value sent is ether higher than max bid and min price set by seller/creator.
        require(
            msg.value >= voucherToBids[_voucherId].highestBid &&
                msg.value >= voucher.minPrice,
            "send more eth than highestBid"
        );

        // // owner can not bid on it own listed nft.
        // require(msg.sender != voucher.creator, "creator not allowed!");

        // // make sure signature is valid and get the address of the signer
        address signer = _verify(voucher);
        require(msg.sender != signer, "creator not allowed!");

        uint256 _tokenId = nftContract.redeem(redeemer, voucher);
        //saving value to be withdrawn later by the nft creator/signer
        drawableSeller[signer].eth += msg.value;

        emit MarketItemSold(signer, redeemer, _tokenId, msg.value);

        return _tokenId;
    }

    function buyNFTVoucherNowWithERC20() public {}

    function makeAbidOnNFTVoucherWithETH(
        NFTVoucher calldata voucher,
        uint256 _voucherId
    ) public payable {
        require(
            msg.value > voucherToBids[_voucherId].highestBid &&
                msg.value > voucher.minPrice,
            "Bid higher"
        );

        address signer = _verify(voucher);
        require(msg.sender != signer, "creator not allowed!");
        // require(msg.sender != voucher.creator, "creator not allowed");

        voucherToBids[_voucherId].highestBid = msg.value;
        voucherToBids[_voucherId].bidders.push(msg.sender);
        drawablesBidder[msg.sender].eth += msg.value;
    }

    function makeAbidOnNFTVoucherWithERC20(
        NFTVoucher calldata voucher,
        uint256 _tokenId,
        uint256 _cost,
        address _paymentToken
    ) public {
        require(
            _cost > voucherToBids[_tokenId].highestBid &&
                _cost > voucher.minPrice,
            "Market: Bid more ERC20"
        );

        address signer = _verify(voucher);
        require(msg.sender != signer, "creator not allowed!");
        // require(msg.sender != voucher.creator, "creator not allowed");

        voucherToBids[_tokenId].highestBid = _cost;
        voucherToBids[_tokenId].paymentToken = _paymentToken;
        voucherToBids[_tokenId].bidders.push(msg.sender);
        drawablesBidder[msg.sender].erc += _cost;
    }

    /** @dev NFT seller can accept a bid with Eth from a bidder. This skips the highest bidder check */
    /** @dev Eth value is stored in pendingWithdrawls mapping to signer(seller here) to be witdrawn anytime */

    function acceptTheHeighestBidOnTheNFTVoucher(
        address redeemer,
        NFTVoucher calldata voucher,
        uint256 _ercTokenValue
    ) public payable onlyRole(MINTER_ROLE) returns (uint256) {
        // owner can not bid on it own listed nft.
        // require(msg.sender != voucher.creator, "creator not allowed!");

        // make sure signature is valid and get the address of the signer
        address signer = _verify(voucher);
        require(msg.sender == signer, "Only Signer or Minter");

        uint256 _tokenId = nftContract.redeem(redeemer, voucher);
        //saving value to be withdrawn later by the nft creator/signer
        if (msg.value != 0) {
            drawableSeller[signer].eth += msg.value;
        } else {
            drawableSeller[signer].erc = _ercTokenValue;
        }
        emit MarketItemSold(signer, redeemer, _tokenId, msg.value);

        return _tokenId;
    }

    // function buyNowVoucher(address to, uint256 _tokenId) public payable {
    //     require(msg.sender != address(0));

    //     if (msg.value != 0) {
    //         require(msg.value >= voucher.minPrice && msg.value >= tokenIdtoMarketItem[voucher.tokenId].bid.highestBid );
    //         nftContract.redeem(to, voucher, msg.value);

    //         // And the end of the _redeem function above the Ethe value sent with by caller is stored in the smart contract in _redeem function
    //         // and can be withdrawable by the creator of the nft anytime
    //     } else {
    //         uint256 _minPrice;

    //         if (bids[voucher.tokenId].highestBid > voucher.minPrice) {
    //             _minPrice = bids[voucher.tokenId].highestBid;
    //         } else {
    //             _minPrice = voucher.minPrice;
    //         }

    //         voucher.paymentToken.safeTransferFrom(
    //             msg.sender,
    //             voucher.creator,
    //             _minPrice
    //         );

    //         _redeem(msg.sender, voucher);
    //     }
    // }

    /** @notice -----------------------------------------------------NFT VOUCHER FUNCTIONS END HERE------------------------------------------------- */

    /** @notice ---------------------------------------------------trnasfer the NFT to highets bidder------------------------------------------------*/

    // function _transferAsset(IERC721 _nft, uint256 _tokenId) private {
    //     address highestBidder = tokenIdToMarketItem[_tokenId].bidders[
    //         tokenIdToMarketItem[_tokenId].bidders.length - 1
    //     ];

    //     address seller = tokenIdToMarketItem[_tokenId].creator;

    //     _nft.transferFrom(seller, highestBidder, _tokenId);
    // }

    /**@notice ------------------------------------------------------ asset transfer complete------------------------------------------------------- */
    /// @notice Mint nft onchain without Lazymint and list on the  market

    function changeListingFee(uint256 _fee)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        listingFee = _fee;
    }

    /** @notice ---------------------------------Functions to withdraw Ether or ERC20 to cretor/seller account --------------------------------------- */

    /// @notice Transfers all pending withdrawal balance to the caller. Reverts if the caller is not an authorized minter.

    function withdrawEther() public {
        require(
            hasRole(MINTER_ROLE, msg.sender),
            "Only authorized minters can withdraw"
        );

        // IMPORTANT: casting msg.sender to a payable address is only safe if ALL members of the minter role are payable addresses.
        address payable seller = payable(msg.sender);
        require(seller != address(0));

        uint256 amount = drawableSeller[seller].eth;
        // zero account before transfer to prevent re-entrancy attack
        drawableSeller[seller].eth = 0;

        (bool sent, ) = seller.call{value: amount}("");

        require(sent, "Market: Eth TF");
    }

    function withdrawERC20(address _ERC20token) public returns (bool) {
        require(
            hasRole(MINTER_ROLE, msg.sender),
            "Only authorized minters can withdraw"
        );

        address payable receiver = payable(msg.sender);

        require(receiver != address(0), "Market: invalid address");
        uint256 amount = pendingWithdrawalsERC20[receiver][_ERC20token];
        pendingWithdrawalsERC20[receiver][_ERC20token] = 0;

        bool success = IERC20(_ERC20token).transfer(receiver, amount);

        require(success, "Market: ERC20 TF.");

        return success;
    }

    /// @notice Retuns the amount of Ether available to the caller to withdraw.
    function availableToWithdrawSeller()
        public
        view
        returns (uint256 ethAmount, uint256 ercAmount)
    {
        return (drawableSeller[msg.sender].eth, drawableSeller[msg.sender].erc);
    }

    /// @notice Retuns the amount of Ether available to the caller to withdraw.

    function availableToWithdrawBidder()
        public
        view
        returns (uint256 ethAmount, uint256 erc20Amount)
    {
        return (
            drawablesBidder[msg.sender].eth,
            drawablesBidder[msg.sender].erc
        );
    }

    /** @notice---------------------------------------------------Withdraw fuctions end here------------------------------------------------------------- */

    /** @notice -----------------------------------------------------View functions---------------------------------------------------------------------- */

    function getBidsOnAVoucher(uint256 _tokenId)
        public
        view
        returns (Bid memory bid)
    {
        return voucherToBids[_tokenId];
    }

    // The following functions are overrides required by Solidity.

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    /** --------------------------------------------------------To Withdraw bid ------------------------------------------------------------------- */

    function revokeMarketItem(uint256 _tokenId) public onlyRole(MINTER_ROLE) {

        
    }

    /** @notice ------------------------------------------------External function starts ----------------------------------------------------------- */

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

    /** @notice ------------------------------------------------External function Ends here ----------------------------------------------------------- */

    /** @notice ------------------------------------------------Internal functions -------------------------------------------------------------------- */

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

    function updateNFTContractAddress(address _newAddress)
        external
        onlyRole(PAUSER_ROLE)
    {
        nftContract = ILazyNFT(_newAddress);
    }

    /** @notice ------------------------------------------------Internal functions Ends here------------------------------------------------------------------ */
}
