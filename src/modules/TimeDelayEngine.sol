
import "../interfaces/ITimeDelayEngine.sol";


contract TimeDelayEngine is ITimeDelayEngine {


    uint256 public constant MINIMUN_DELAY    = 2 days;
    uint256 public constant MAXIXUM_DELAY    = 30 days;
    uint256 public constant EXTENDED_PERIOD = 14 days; // execution window after eta

    bool private _locked;

    address public immutable coordinator;

    mapping(bytes32 => TimelockEntry) private _entries;

    modifier onlyCoordinator() {
        if (msg.sender != coordinator) revert TL_OnlyCoordinator();
        _;
    }

    modifier nonReentrant() {
        if (_locked) revert TL_Reentrant();
        _locked = true;
        _;
        _locked = false;
    }



error TL_DelayOutOfRange();
error TL_AlreadyQueued();
error TL_OnlyCoordinator();
error TL_Reentrant();



 function queue(bytes32 proposalId, uint256 delay)
        external
        onlyCoordinator
        nonReentrant
        returns (uint256 eta)
    {
        if (delay < MINIMUN_DELAY || delay > MAXIXUM_DELAY) revert TL_DelayOutOfRange();

        TimelockEntry storage e = _entries[proposalId];
        if (e.queuedAt != 0) revert TL_AlreadyQueued();

        eta = block.timestamp + delay;
        uint256 expiresAt = eta + EXTENDED_PERIOD;
        _entries[proposalId] = TimelockEntry({
            proposalId: proposalId,
            queuedAt:   block.timestamp,
            eta:        eta,
            expiresAt:  expiresAt,
            executed:   false,
            cancelled:  false
        });

        emit EntryQueued(proposalId, eta, expiresAt);
    }



}