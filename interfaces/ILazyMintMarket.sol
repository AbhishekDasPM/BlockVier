//SPDX-License-Identifier: MIT
pragma solidity =0.8.13;

// import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface ILazymintMarket {
    // mapping(address => mapping(uint256 => NFTVoucher)) public voucherToAuction;

    // modifier notNftSeller(address _nftContractAddress, uint256 _tokenId) {
    //     require(
    //         msg.sender != voucherToAuction[nftAddress][tokenId].creator,
    //         "Owner cannot bid on own NFT"
    //     );
    // }

    // /// @notice Represents an un-minted NFT, which has not yet been recorded into the blockchain. A signed voucher can be redeemed for a real NFT using the redeem function.
    // struct NFTVoucher {
    //     /// @notice The id of the token to be redeemed. Must be unique - if another token with this ID already exists, the redeem function will revert.
    //     uint256 tokenId;
    //     /// @notice The minimum price (in wei) that the NFT creator is willing to accept for the initial sale of this NFT.
    //     uint256 minPrice;
    //     /// @notice The metadata URI to associate with this token.
    //     string uri;
    //     /// @notice The address of creator
    //     address creator;
    //     /// @notice The address of ERC20 payment token
    //     IERC20 erc20Token;
    //     /// @notice Bid prams

    //     Bid bid;
    //     /// @notice the EIP-712 signature of all other fields in the NFTVoucher struct. For a voucher to be valid, it must be signed by an account with the MINTER_ROLE.
    //     bytes signature;
    // }

    // struct Auction {
    //     //map token ID to
    //     uint32 bidIncreasePercentage;
    //     uint32 auctionBidPeriod; //Increments the length of time the auction is open in which a new bid can be made after each bid.
    //     uint64 auctionEnd;
    //     uint128 minPrice;
    //     uint128 buyNowPrice;
    //     uint128 nftHighestBid;
    //     address nftHighestBidder;
    //     address nftSeller;
    //     address whitelistedBuyer; //The seller can specify a whitelisted address for a sale (this is effectively a direct sale).
    //     address nftRecipient; //The bidder can specify a recipient for the NFT if their bid is successful.
    //     address ERC20Token; // The seller can specify an ERC20 token that can be used to bid or purchase the NFT.
    //     address[] feeRecipients;
    //     uint32[] feePercentages;
    // }

    // struct MarketItem {
    //     uint256 tokenId;
    //     uint256 minPrice;
    //     uint256 buyNowPrice;
    //     string uri;
    //     address payable creator;
    //     address payable buyer;
    //     PaymentToken paymentToken;
    //     uint256 bidStartsAt;
    //     uint256 bidEndsAt;
    //     uint256 highestBid;
    //     bool isBidActive;
    //     bool bidSuccess;
    //     address[] highestBidders;
    //     //Bid bid;
    //     bool isERC20exits;
    //     bool isListed;
    // }

    struct Drawable {
        uint256 eth;
        uint256 erc;
    }

    struct PaymentToken {
        address tokenAddress;
        uint256 cost;
    }

    struct Bid {
        uint256 bidStartsAt;
        uint256 bidEndsAt;
        uint256 highestBid;
        bool isBidActive;
        bool bidSuccess;
        bool bidInit;
        address[] bidders;
        address paymentToken;
    }

    struct MarketItem {
        uint256 tokenId;
        uint256 minPrice;
        uint256 buyNowPrice;
        string uri;
        address payable creator;
        address payable buyer;
        PaymentToken paymentToken;
        uint256 bidStartsAt;
        uint256 bidEndsAt;
        uint256 highestBid;
        bool isBidActive;
        address[] bidders;
        //Bid bid;
        bool isERC20exits;
        bool isListed;
    }

    event MarketItemCreated(
        address indexed creator,
        uint256 indexed tokenId,
        uint256 indexed minPrice,
        uint256 buyNowPrice
    );

    event MarketItemCancelled(address indexed creator, uint256 indexed tokenId);

    event MarketItemSold(
        address indexed seller,
        address indexed buyer,
        uint256 indexed tokenId,
        uint256 sellPrice
    );

    event BidMade(
        address indexed Bidder,
        uint256 indexed BidAmount,
        uint256 indexed tokenId
    );

    event ERC20withdrawal(
        address indexed receiever,
        uint256 indexed amount,
        address indexed _ERC20token
    );
    event Etherwithdrawal(address indexed receiver, uint256 indexed value);
    event EtherReceived(address indexed sender, uint256 indexed value);

    // function buyNowOption(NFTVoucher calldata voucher) external payable;

    // function makeAbid(NFTVoucher memory voucher, uint256 _newBidAmount)
    //     external
    //     payable;

    // function createMarketItemOnchainAndList() external;
}
