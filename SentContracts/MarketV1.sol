//SPDX-License-Identifier: MIT
pragma solidity =0.8.13;

pragma abicoder v2; // required to accept structs as function parameters

// import "./AbstractBaseNFT.sol";

// import "./LazyNFT.sol";

// interface ILazyNFT is IERC721 {
//     function redeem(address redeemer, NFTVoucher calldata voucher)
//         external
//         returns (uint256);
// }
// import {NFTVoucher} from "./LazyNFT.sol";

import "../interfaces/ILazyMintMarket.sol";
import "../interfaces/ILazyNFT.sol";

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

contract Market is
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

    // to keep track of all marketitems created with unique on-chain NFT id. Note: does not keep track of NFT vouchers as they are not minted yet.
    mapping(uint256 => MarketItem) public tokenIdToMarketItem;

    // mapping(address => mapping(uint256 => MarketItem)) public nftToMarketItem;
    // mapping(uint256 => NFTVoucher) public tokenIdToNFTVoucher;

    mapping(uint256 => address) public tokenIdToNFTcontract;

    // mapping(uint256 => MarketItem) public tokenIdToMarketItem;

    // to keep track of bids made on each on-chain minted nft til now
    // mapping(uint256 => MarketItem) public tokenIdToBids;

    // to keep track of bids made on each voucher
    // mapping(uint256 => MarketItem) public voucherIdToBids;

    mapping(uint256 => Bid) public voucherToBids;

    /** --------------------------------------------------------------------constructor-------------------------------------------------------- */

    constructor(address _nftContract)
        EIP712(SIGNING_DOMAIN_NAME, SIGNING_DOMAIN_VERSION)
    {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);

        require(isContract(_nftContract), "invalid address.");

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

    /** @dev ERC721 implementaions */

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
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

    /** -----------------------------------------------------NFT VOUCHER RELATED FUNCTIONS START HERE------------------------------------------ */

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
    ) public payable nonReentrant onlyRole(MINTER_ROLE) returns (uint256) {
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

    /** ----------------------------------------------------------NFT VOUCHER FUNCTIONS END HERE------------------------------------------------- */

    /** -------------------------------------------------------NON-LAZY/NORMAL MINT RELATED FUNCTION START HERE---------------------------------------- */

    /** @dev Create a market item for NON Lazy mint */

    function createMarketItemforNormalMintWithEtherPrice(
        uint256 _tokenId,
        uint256 _price,
        uint256 _buyNowPrice,
        string memory _uri,
        uint256 _bidStartsAt,
        uint256 _bidEndsAt,
        address[] calldata _highestBidder,
        address _nftContract
    ) public payable {
        require(
            (IERC721(_nftContract).ownerOf(_tokenId) == msg.sender),
            "Market: Only-NFT-owner"
        );
        require(msg.value == listingFee, "listing fee required.");
        require(msg.sender != address(0), "Invalid address!");

        require(!tokenIdToMarketItem[_tokenId].isListed, "already listed!");

        tokenIdToMarketItem[_tokenId] = MarketItem({
            tokenId: _tokenId,
            minPrice: _price,
            buyNowPrice: _buyNowPrice,
            uri: _uri,
            creator: payable(_msgSender()),
            buyer: payable(address(0)),
            paymentToken: PaymentToken(address(0), 0),
            bidStartsAt: _bidStartsAt,
            bidEndsAt: _bidEndsAt,
            highestBid: 0,
            isBidActive: true,
            bidders: _highestBidder,
            isERC20exits: false,
            isListed: true
        });

        tokenIdToNFTcontract[_tokenId] = _nftContract;

        emit MarketItemCreated(msg.sender, _tokenId, _price, _buyNowPrice);

        // tokenIdtoMarketItem[_tokenId] = marketItems[marketItems.length - 1];
    }

    function createMarketItemforNormalMintWithERC20tokenPrice(
        address _paymentToken,
        address _nftContract,
        uint256 _tokenId,
        uint256 _cost,
        uint256 _buyNowPrice,
        string memory _uri,
        uint256 _bidStartsAt,
        uint256 _bidEndsAt,
        address[] calldata _highestBidder
    ) public payable {
        require(
            (IERC721(_nftContract).ownerOf(_tokenId) == msg.sender),
            "Only-owner"
        );
        require(msg.value == listingFee, "listing fee required.");

        require(isContract(_paymentToken), "Market: invalid ERC20");
        require(isContract(_nftContract), "Market: invalid ERC721");
        require(msg.sender != address(0), "zero address!");
        require(!tokenIdToMarketItem[_tokenId].isListed, "already listed!");

        tokenIdToMarketItem[_tokenId] = MarketItem({
            tokenId: _tokenId,
            minPrice: _cost,
            buyNowPrice: _buyNowPrice,
            uri: _uri,
            creator: payable(_msgSender()),
            buyer: payable(address(0)),
            paymentToken: PaymentToken(_paymentToken, _cost),
            bidStartsAt: _bidStartsAt,
            bidEndsAt: _bidEndsAt,
            highestBid: 0,
            isBidActive: true,
            bidders: _highestBidder,
            isERC20exits: true,
            isListed: true
        });

        tokenIdToNFTcontract[_tokenId] = _nftContract;

        emit MarketItemCreated(msg.sender, _tokenId, _cost, _buyNowPrice);

        // tokenIdtoMarketItem[_tokenId] = marketItems[marketItems.length - 1];
    }

    /// @notice To start a Bid for an nft

    function makeAbid(
        address _nftContract,
        uint256 _tokenId,
        uint256 _newBidinERC20
    ) public payable nonReentrant {
        require(msg.sender != address(0), "Invalid address");

        require(
            tokenIdToMarketItem[_tokenId].isListed &&
                tokenIdToMarketItem[_tokenId].isBidActive,
            "Market: Not available."
        );

        require(
            tokenIdToMarketItem[_tokenId].bidEndsAt > block.timestamp,
            "Bid already ended."
        );
        // require(tokenIdToNFTVoucher[_uuId].isActive, "bid not active");

        // Can't bid on your own NFT

        require(
            _msgSender() != IERC721(_nftContract).ownerOf(_tokenId),
            "owner not allowed"
        );

        if (msg.value != 0) {
            require(
                !tokenIdToMarketItem[_tokenId].isERC20exits,
                "Market: ERC20 payment only "
            );

            require(
                msg.value > tokenIdToMarketItem[_tokenId].highestBid &&
                    msg.value >= tokenIdToMarketItem[_tokenId].minPrice,
                "Increase ETH value"
            );
            emit BidMade(msg.sender, msg.value, _tokenId);

            drawablesBidder[msg.sender].eth += msg.value;

            tokenIdToMarketItem[_tokenId].highestBid = msg.value;
            tokenIdToMarketItem[_tokenId].bidders.push(msg.sender);
            tokenIdToMarketItem[_tokenId].isBidActive = true;
        } else {
            require(tokenIdToMarketItem[_tokenId].isERC20exits);

            // check to ensure bid amount is higher than the last highest bid
            //  if the biddier is the very first bidder, then the bid must be higher than the cost set by the seller in PaymentToken struct //

            require(
                _newBidinERC20 >=
                    tokenIdToMarketItem[_tokenId].paymentToken.cost &&
                    _newBidinERC20 >= tokenIdToMarketItem[_tokenId].highestBid,
                "bid higher ERC20"
            );

            emit BidMade(msg.sender, _newBidinERC20, _tokenId);

            // Transferring ERC20 to marketpalce
            bool success = IERC20(
                tokenIdToMarketItem[_tokenId].paymentToken.tokenAddress
            ).transferFrom(msg.sender, address(this), _newBidinERC20);

            require(success, "Market: ERC20 F=TF");

            drawablesBidder[msg.sender].erc = _newBidinERC20;

            tokenIdToMarketItem[_tokenId].bidders.push(msg.sender);

            tokenIdToMarketItem[_tokenId].highestBid = _newBidinERC20;
            // pendingERC20Withdrawals[msg.sender] = _newBidinERC20;

            // pendingWithdrawalsERC20[msg.sender][
            //     tokenIdToMarketItem[_tokenId].paymentToken.tokenAddress
            // ] = _newBidinERC20;
            tokenIdToMarketItem[_tokenId].isBidActive = true;
        }
    }

    function acceptBidNonLazyNFT(IERC721 _nftContract, uint256 _tokenId)
        public
        nonReentrant
    {
        /**@dev Sanity check------------------- */
        require(
            hasRole(MINTER_ROLE, msg.sender),
            "Only authorized minters can withdraw"
        );
        require(
            tokenIdToMarketItem[_tokenId].isListed &&
                tokenIdToMarketItem[_tokenId].isBidActive,
            "Market: id not listed or no bid on it"
        );
        address payable seller = payable(msg.sender);
        require(seller != address(0), "caller zero address.");

        address highestBidder = tokenIdToMarketItem[_tokenId].bidders[
            tokenIdToMarketItem[_tokenId].bidders.length - 1
        ];

        /**@dev end of sanit check------------------- */

        /** @dev tranfer of value and assets starts */

        if (tokenIdToMarketItem[_tokenId].isERC20exits) {
            // uint256 amount = pendingWithdrawalsERC20[
            //     tokenIdToMarketItem[_tokenId].highestBidders[
            //         tokenIdToMarketItem[_tokenId].highestBidders.length - 1
            //     ]
            // ][address(_nftContract)];

            // Alternative to above. Either of them must work.

            uint256 amount = tokenIdToMarketItem[_tokenId].highestBid;

            address erc20Token = tokenIdToMarketItem[_tokenId]
                .paymentToken
                .tokenAddress;

            emit MarketItemSold(seller, highestBidder, _tokenId, amount);



            // transfer value

            bool success1 = IERC20(erc20Token).transfer(seller, amount);
            require(success1, "IERC20: TF");

            //deducting withdrawable ERC20 balance 'amount' from highest bidder

            drawablesBidder[highestBidder].erc -= amount;

            //transfer asset

            _transferAsset(_nftContract, _tokenId);

            // to reset all value to zero for the token-Id sold

            revokeMarketItem(_tokenId);
        } else {
            // storing  highest bid into 'amount' of Eth to send it to seller
            uint256 amount = tokenIdToMarketItem[_tokenId].highestBid;

            emit MarketItemSold(seller, highestBidder, _tokenId, amount);

            // sending the Eth to seller

            (bool success2, ) = seller.call{value: amount, gas: 2300}("");

            require(success2, "Market: Ether TF");

            //deducting withdrawable Eth balance 'amount' from highest bidder
            drawablesBidder[highestBidder].eth -= amount;

            // transeferring NFT to highest bidder

            _transferAsset(_nftContract, _tokenId);

            // to reset all value to zero for the token Id sole

            revokeMarketItem(_tokenId);
        }

        /** @dev tranfer of value and assets Ends */
    }

    /** --------------------@dev trnasfer the NFT to highets bidder------------------------------*/

    function _transferAsset(IERC721 _nft, uint256 _tokenId) private {
        address highestBidder = tokenIdToMarketItem[_tokenId].bidders[
            tokenIdToMarketItem[_tokenId].bidders.length - 1
        ];

        address seller = tokenIdToMarketItem[_tokenId].creator;

        _nft.transferFrom(seller, highestBidder, _tokenId);
    }

    /**-------------------------@dev asset transfer complete------------------------------------------ */
    /// @notice Mint nft onchain without Lazymint and list on the  market

    function changeListingFee(uint256 _fee)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        listingFee = _fee;
    }

    /** @dev ---------------------------------Functions to withdraw Ether or ERC20 to cretor/seller account ----------------------------------- */

    /// @notice Transfers all pending withdrawal balance to the caller. Reverts if the caller is not an authorized minter.

    function withdrawEther() public nonReentrant {
        require(
            hasRole(MINTER_ROLE, msg.sender),
            "Only authorized minters can withdraw"
        );

        // IMPORTANT: casting msg.sender to a payable address is only safe if ALL members of the minter role are payable addresses.
        address payable seller = payable(msg.sender);
        require(seller != address(0));

        uint256 amount = drawableSeller[seller].eth;

        /// @dev Emitting Etherwithdrawal event before state change to  Ether balance of caller
        emit Etherwithdrawal(msg.sender, amount);

        // zero account before transfer to prevent re-entrancy attack
        drawableSeller[seller].eth = 0;

        (bool sent, ) = seller.call{value: amount}("");

        require(sent, "Market: Eth TF");
    }

    function withdrawERC20(address _ERC20token)
        public
        nonReentrant
        returns (bool)
    {
        require(
            hasRole(MINTER_ROLE, msg.sender),
            "Only authorized minters can withdraw"
        );

        address payable receiver = payable(msg.sender);

        require(receiver != address(0), "Market: invalid address");
        uint256 amount = pendingWithdrawalsERC20[receiver][_ERC20token];

        /// @dev Emitting ERC20withdrawal before state changes to ERC20 balance of caller
        emit ERC20withdrawal(msg.sender, amount, _ERC20token);

        /// @dev make state changes before transferring ERC20 token
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

    /** ---------------------------------------------------Withdraw fuctions end here----------------------------------------------------------- */

    /** ----------------------------To Withdraw bid -------------------------------------- */

    function revokeMarketItem(uint256 _tokenId) public onlyRole(MINTER_ROLE) {
        tokenIdToMarketItem[_tokenId].minPrice = 0;
        tokenIdToMarketItem[_tokenId].buyNowPrice = 0;
        tokenIdToMarketItem[_tokenId].uri = "";
        tokenIdToMarketItem[_tokenId].creator = payable(0);
        tokenIdToMarketItem[_tokenId].buyer = payable(0);
        tokenIdToMarketItem[_tokenId].paymentToken.tokenAddress = address(0);
        tokenIdToMarketItem[_tokenId].bidStartsAt = 0;
        tokenIdToMarketItem[_tokenId].bidEndsAt = 0;
        tokenIdToMarketItem[_tokenId].highestBid = 0;
        tokenIdToMarketItem[_tokenId].isBidActive = false;
        delete tokenIdToMarketItem[_tokenId].bidders; // or tokenIdToMarketItem[_tokenId].highestBidders.length = 0;
        tokenIdToMarketItem[_tokenId].isERC20exits = false;
        tokenIdToMarketItem[_tokenId].isListed = false;
    }

    /** @dev -----------------------------------NFT voucher verification related function starts here------------------------------------------ */
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

    /** @dev Required for any contract which needs to receive Ehter value */

    receive() external payable {
        emit EtherReceived(msg.sender, msg.value);
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

    /** ----------------------------------NFT voucher verification related function starts here--------------------------------------------- */
}
