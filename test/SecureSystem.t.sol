// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

import "../src/modules/Authorization.sol";
import "../src/modules/TimeDelayEngine.sol";
import "../src/modules/RewardDistributor.sol";
import "../src/core/SecureTreasuryExecution.sol";
import "../src/interfaces/IAction.sol";
import "../src/interfaces/ITimeDelayEngine.sol";
import "../src/libraries/MerkleLib.sol";

// ══════════════════════════════════════════════════════════════════════════════
//  Mocks
// ══════════════════════════════════════════════════════════════════════════════

contract MockActionManager {
    bytes32 internal constant MOCK_ID = keccak256("mock-proposal");

    function propose(
        address,
        IAction.ProposalAction[] calldata,
        uint256
    ) external pure returns (bytes32) {
        return MOCK_ID;
    }
}

contract MockGov {
    bool public _paused;

    function isPaused() external view returns (bool) { return _paused; }
    function setPaused(bool v) external { _paused = v; }
}

contract MockERC20 {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amt) external { balanceOf[to] += amt; }

    function transfer(address to, uint256 amt) external returns (bool) {
        require(balanceOf[msg.sender] >= amt, "insufficient");
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        return true;
    }

    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
        return true;
    }
}

/// @dev Attempts to re-enter claim() when ETH is received
contract ReentrantClaimer {
    RewardDistributor public rd;
    uint256           public epochId;
    uint256           public amount;
    bytes32[]         public proof;
    bool              public reentered;

    constructor(address _rd) { rd = RewardDistributor(_rd); }

    function prime(uint256 _epochId, uint256 _amount, bytes32[] calldata _proof) external {
        epochId = _epochId;
        amount  = _amount;
        proof   = _proof;
    }

    function attack() external {
        rd.claim(epochId, address(this), amount, proof);
    }

    receive() external payable {
        if (!reentered) {
            reentered = true;
            try rd.claim(epochId, address(this), amount, proof) {} catch {}
        }
    }
}

// ── Harness: exposes internal execution functions ─────────────────────────────
contract TreasuryHarness is SecureTreasuryExecution {
    constructor(address am) SecureTreasuryExecution(am) {}

    function executeTransfer(IAction.ProposalAction memory action, uint256 idx) external {
        _executeTransfer(action, idx);
    }

    function executeCall(IAction.ProposalAction memory action, uint256 idx) external {
        _executeCall(action, idx);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Main Test Contract
// ══════════════════════════════════════════════════════════════════════════════

contract SecureSystemTest is Test {

    // ── Key material ─────────────────────────────────────────────────────────
    uint256 internal constant SIGNER_PK     = 0xA11CE;
    uint256 internal constant ATTACKER_PK   = 0xBAD;
    address internal          SIGNER;
    address internal          ATTACKER;

    // ── Contracts ────────────────────────────────────────────────────────────
    Authorization    auth;
    TimeDelayEngine  tde;
    RewardDistributor rd;
    TreasuryHarness  treasury;
    MockActionManager mockAction;
    MockGov           mockGov;
    MockERC20         token;

    // ─────────────────────────────────────────────────────────────────────────
    //  Storage layout notes (used by vm.store helpers):
    //
    //  Authorization   : _signers(slot 0), _proposalApprovals(slot 1)
    //  TimeDelayEngine : _locked(slot 0),  _entries(slot 1)
    //  RewardDistributor: _claimed(slot 0), _epochs(slot 1)
    //  SecureTreasuryExecution: govPrevention(slot 0), actionManager(slot 1)
    //
    //  Both Authorization.coordinator and TimeDelayEngine.coordinator are
    //  immutables that are never assigned in a constructor, so they default
    //  to address(0). All coordinator-gated calls use vm.prank(address(0)).
    // ─────────────────────────────────────────────────────────────────────────

    function setUp() public {
        SIGNER   = vm.addr(SIGNER_PK);
        ATTACKER = vm.addr(ATTACKER_PK);

        auth    = new Authorization();
        tde     = new TimeDelayEngine();
        rd      = new RewardDistributor();
        token   = new MockERC20();

        mockAction = new MockActionManager();
        mockGov    = new MockGov();

        treasury = new TreasuryHarness(address(mockAction));

        // Wire govPrevention into treasury (slot 0)
        vm.store(
            address(treasury),
            bytes32(uint256(0)),
            bytes32(uint256(uint160(address(mockGov))))
        );
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  HELPERS
    // ══════════════════════════════════════════════════════════════════════════

    /// Activate a signer in Authorization via direct storage write.
    /// SignerState { bool active; uint256 nonce; } at keccak256(addr, slot 0).
    function _activateSigner(address signer) internal {
        bytes32 slot = keccak256(abi.encode(signer, uint256(0)));
        vm.store(address(auth), slot, bytes32(uint256(1))); // active=true, nonce=0
    }

    /// Build an EIP-712 digest matching SignatureLib (domainSeparator == bytes32(0)
    /// because the immutable is never set in the constructor).
    function _buildDigest(
        bytes32 proposalId,
        bytes32 actionsHash,
        address signer,
        uint256 nonce
    ) internal view returns (bytes32) {
        bytes32 APPROVAL_TYPEHASH = keccak256(
            "ProposalApproval("
            "bytes32 proposalId,"
            "bytes32 actionsHash,"
            "address signer,"
            "uint256 signerNonce,"
            "uint256 chainId"
            ")"
        );
        bytes32 structHash = keccak256(abi.encode(
            APPROVAL_TYPEHASH,
            proposalId,
            actionsHash,
            signer,
            nonce,
            block.chainid
        ));
        return keccak256(abi.encodePacked("\x19\x01", bytes32(0), structHash));
    }

    /// Sign and pack into the 65-byte r||s||v format expected by SignatureLib.
    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// Build a two-leaf Merkle tree for (recipient, amount) and return
    /// the root plus the proof needed to verify that leaf.
    function _buildMerkle(address recipient, uint256 amount)
        internal
        pure
        returns (bytes32 root, bytes32[] memory proof)
    {
        bytes32 leaf0 = MerkleLib.computeLeaf(recipient, amount);
        bytes32 leaf1 = MerkleLib.computeLeaf(address(0xdead), 1);

        (bytes32 lo, bytes32 hi) = leaf0 < leaf1 ? (leaf0, leaf1) : (leaf1, leaf0);
        root = keccak256(abi.encodePacked(lo, hi));

        proof    = new bytes32[](1);
        proof[0] = leaf1; // sibling; verify() sorts internally
    }

    /// Seed a RewardEpoch directly into private storage.
    /// RewardEpoch slot base = keccak256(abi.encode(epochId, 1))
    ///   +0 merkleRoot  +1 token  +2 totalDeposited  +3 totalClaimed
    ///   +4 createdAt   +5 finalized
    function _seedEpoch(
        uint256 epochId,
        bytes32 merkleRoot,
        address tokenAddr,
        uint256 totalDeposited
    ) internal {
        bytes32 base = keccak256(abi.encode(epochId, uint256(1)));
        vm.store(address(rd), bytes32(uint256(base)),       merkleRoot);
        vm.store(address(rd), bytes32(uint256(base) + 1),   bytes32(uint256(uint160(tokenAddr))));
        vm.store(address(rd), bytes32(uint256(base) + 2),   bytes32(totalDeposited));
        vm.store(address(rd), bytes32(uint256(base) + 4),   bytes32(uint256(1))); // createdAt != 0
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  FUNCTIONAL TESTS
    // ══════════════════════════════════════════════════════════════════════════

    // ── 1. Proposal lifecycle ─────────────────────────────────────────────────

    function test_Propose_ReturnsId() public {
        IAction.ProposalAction[] memory acts = new IAction.ProposalAction[](1);
        acts[0] = IAction.ProposalAction({
            actionType: IAction.ActionType.TRANSFER,
            target:     address(token),
            recipient:  address(this),
            value:      0,
            amount:     100e18,
            callData:   ""
        });

        bytes32 id = treasury.propose(acts, 3 days);
        assertEq(id, keccak256("mock-proposal"));
    }

    function test_Propose_EmitsEvent() public {
        IAction.ProposalAction[] memory acts = new IAction.ProposalAction[](0);

        vm.expectEmit(true, true, false, false, address(treasury));
        emit SecureTreasuryExecution.Proposal(keccak256("mock-proposal"), address(this));
        treasury.propose(acts, 3 days);
    }

    function test_Propose_RevertsWhenPaused() public {
        mockGov.setPaused(true);
        IAction.ProposalAction[] memory acts = new IAction.ProposalAction[](0);
        vm.expectRevert(bytes("AT: Paused"));
        treasury.propose(acts, 3 days);
    }

    // ── 2. Signature verification ─────────────────────────────────────────────

    function test_Signature_ValidSig_Accepted() public {
        bytes32 proposalId  = keccak256("prop-1");
        bytes32 actionsHash = keccak256("actions-1");
        _activateSigner(SIGNER);

        bytes memory sig = _sign(SIGNER_PK, _buildDigest(proposalId, actionsHash, SIGNER, 0));

        address[] memory signers = new address[](1);
        bytes[]   memory sigs    = new bytes[](1);
        signers[0] = SIGNER;
        sigs[0]    = sig;

        vm.prank(address(0));
        (uint256 validCount, address[] memory validSigners) =
            auth.verifyAndConsume(proposalId, actionsHash, signers, sigs);

        assertEq(validCount, 1);
        assertEq(validSigners[0], SIGNER);
    }

    function test_Signature_EmitsSignatureConsumed() public {
        bytes32 proposalId  = keccak256("prop-emit");
        bytes32 actionsHash = keccak256("actions-emit");
        _activateSigner(SIGNER);

        bytes memory sig = _sign(SIGNER_PK, _buildDigest(proposalId, actionsHash, SIGNER, 0));

        address[] memory signers = new address[](1);
        bytes[]   memory sigs    = new bytes[](1);
        signers[0] = SIGNER;
        sigs[0]    = sig;

        vm.expectEmit(true, true, false, true, address(auth));
        emit IAuthorizationLayer.SignatureConsumed(SIGNER, proposalId, 0);

        vm.prank(address(0));
        auth.verifyAndConsume(proposalId, actionsHash, signers, sigs);
    }

    function test_Signature_NonceIncrements_AfterConsumption() public {
        bytes32 proposalId  = keccak256("prop-nonce");
        bytes32 actionsHash = keccak256("actions-nonce");
        _activateSigner(SIGNER);

        bytes memory sig = _sign(SIGNER_PK, _buildDigest(proposalId, actionsHash, SIGNER, 0));

        address[] memory signers = new address[](1);
        bytes[]   memory sigs    = new bytes[](1);
        signers[0] = SIGNER;
        sigs[0]    = sig;

        vm.prank(address(0));
        auth.verifyAndConsume(proposalId, actionsHash, signers, sigs);

        // On a new proposal the nonce is now 1; old sig (nonce=0) against new proposal fails
        bytes32 proposalId2 = keccak256("prop-nonce-2");
        bytes memory staleNonceSig = _sign(SIGNER_PK, _buildDigest(proposalId2, actionsHash, SIGNER, 0));
        sigs[0] = staleNonceSig;

        vm.prank(address(0));
        (uint256 count,) = auth.verifyAndConsume(proposalId2, actionsHash, signers, sigs);
        assertEq(count, 0); // nonce mismatch → rejected
    }

    // ── 3. Timelock ───────────────────────────────────────────────────────────

    function test_Timelock_Queue_ReturnsCorrectEta() public {
        vm.warp(1_000_000);
        bytes32 id = keccak256("tl-1");

        vm.prank(address(0));
        uint256 eta = tde.queue(id, 5 days);

        assertEq(eta, 1_000_000 + 5 days);
    }

    function test_Timelock_Queue_EmitsEvent() public {
        vm.warp(1_000_000);
        bytes32 id = keccak256("tl-2");
        uint256 expectedEta     = 1_000_000 + 7 days;
        uint256 expectedExpires = expectedEta + 14 days;

        vm.expectEmit(true, false, false, true, address(tde));
        emit ITimeDelayEngine.EntryQueued(id, expectedEta, expectedExpires);

        vm.prank(address(0));
        tde.queue(id, 7 days);
    }

    function test_Timelock_MinimumBoundary_Accepted() public {
        vm.prank(address(0));
        tde.queue(keccak256("tl-min"), 2 days); // exactly at minimum → ok
    }

    function test_Timelock_MaximumBoundary_Accepted() public {
        vm.prank(address(0));
        tde.queue(keccak256("tl-max"), 30 days); // exactly at maximum → ok
    }

    // ── 4. Reward claiming ────────────────────────────────────────────────────

    function test_RewardClaim_ETH_TransfersCorrectAmount() public {
        address payable claimant = payable(address(0xBEEF));
        uint256 amount  = 1 ether;
        uint256 epochId = 1;

        (bytes32 root, bytes32[] memory proof) = _buildMerkle(claimant, amount);
        _seedEpoch(epochId, root, address(0), 10 ether);
        vm.deal(address(rd), 10 ether);

        uint256 before = claimant.balance;
        rd.claim(epochId, claimant, amount, proof);
        assertEq(claimant.balance - before, amount);
    }

    function test_RewardClaim_ERC20_TransfersCorrectAmount() public {
        address claimant = address(0xCAFE);
        uint256 amount   = 500e18;
        uint256 epochId  = 2;

        token.mint(address(rd), 1_000e18);
        (bytes32 root, bytes32[] memory proof) = _buildMerkle(claimant, amount);
        _seedEpoch(epochId, root, address(token), 1_000e18);

        rd.claim(epochId, claimant, amount, proof);
        assertEq(token.balanceOf(claimant), amount);
    }

    function test_RewardClaim_EmitsEvent() public {
        address claimant = address(0xABCD);
        uint256 amount   = 0.5 ether;
        uint256 epochId  = 3;

        (bytes32 root, bytes32[] memory proof) = _buildMerkle(claimant, amount);
        _seedEpoch(epochId, root, address(0), 5 ether);
        vm.deal(address(rd), 5 ether);

        vm.expectEmit(true, true, false, true, address(rd));
        emit IRewardDistributor.RewardClaimed(epochId, claimant, amount);
        rd.claim(epochId, claimant, amount, proof);
    }

    // ── 5. Internal execution (via harness) ───────────────────────────────────

    function test_ExecuteTransfer_ETH_SendsValue() public {
        address payable recipient = payable(address(0x1111));
        vm.deal(address(treasury), 5 ether);

        IAction.ProposalAction memory action = IAction.ProposalAction({
            actionType: IAction.ActionType.TRANSFER,
            target:     address(0),   // native ETH
            recipient:  recipient,
            value:      0,
            amount:     2 ether,
            callData:   ""
        });

        treasury.executeTransfer(action, 0);
        assertEq(recipient.balance, 2 ether);
    }

    function test_ExecuteTransfer_ERC20_TransfersToken() public {
        address recipient = address(0x2222);
        token.mint(address(treasury), 100e18);

        IAction.ProposalAction memory action = IAction.ProposalAction({
            actionType: IAction.ActionType.TRANSFER,
            target:     address(token),
            recipient:  recipient,
            value:      0,
            amount:     50e18,
            callData:   ""
        });

        treasury.executeTransfer(action, 0);
        assertEq(token.balanceOf(recipient), 50e18);
    }

    function test_ExecuteCall_ForwardsValue() public {
        // Deploy a simple value receiver
        address payable target = payable(address(new ValueReceiver()));
        vm.deal(address(treasury), 3 ether);

        IAction.ProposalAction memory action = IAction.ProposalAction({
            actionType: IAction.ActionType.CALL,
            target:     target,
            recipient:  address(0),
            value:      1 ether,
            amount:     0,
            callData:   ""
        });

        treasury.executeCall(action, 0);
        assertEq(target.balance, 1 ether);
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  EXPLOIT / ATTACK TESTS
    // ══════════════════════════════════════════════════════════════════════════

    // ── A. Reentrancy on claim ────────────────────────────────────────────────

    function test_Exploit_Reentrancy_SecondClaimReverts() public {
        uint256 amount  = 1 ether;
        uint256 epochId = 10;

        ReentrantClaimer attacker = new ReentrantClaimer(address(rd));
        (bytes32 root, bytes32[] memory proof) = _buildMerkle(address(attacker), amount);
        _seedEpoch(epochId, root, address(0), 10 ether);
        vm.deal(address(rd), 10 ether);

        attacker.prime(epochId, amount, proof);
        attacker.attack();

        // Only the first claim should have gone through
        assertEq(address(rd).balance, 9 ether);
        assertTrue(attacker.reentered(), "receive() was never triggered");
    }

    // ── B. Double claim attempt ───────────────────────────────────────────────

    function test_Exploit_DoubleClaim_Reverts() public {
        address claimant = address(0xABC1);
        uint256 amount   = 2 ether;
        uint256 epochId  = 20;

        (bytes32 root, bytes32[] memory proof) = _buildMerkle(claimant, amount);
        _seedEpoch(epochId, root, address(0), 10 ether);
        vm.deal(address(rd), 10 ether);

        rd.claim(epochId, claimant, amount, proof);

        vm.expectRevert(RewardDistributor.RD_AlreadyClaimed.selector);
        rd.claim(epochId, claimant, amount, proof);
    }

    // ── C. Invalid signature ──────────────────────────────────────────────────

    function test_Exploit_WrongKey_Rejected() public {
        bytes32 proposalId  = keccak256("evil-prop");
        bytes32 actionsHash = keccak256("evil-actions");
        _activateSigner(SIGNER);

        // Attacker signs a digest that claims to be from SIGNER but uses their own key
        bytes memory badSig = _sign(ATTACKER_PK, _buildDigest(proposalId, actionsHash, SIGNER, 0));

        address[] memory signers = new address[](1);
        bytes[]   memory sigs    = new bytes[](1);
        signers[0] = SIGNER;
        sigs[0]    = badSig;

        vm.prank(address(0));
        (uint256 validCount,) = auth.verifyAndConsume(proposalId, actionsHash, signers, sigs);
        assertEq(validCount, 0);
    }

    function test_Exploit_ShortSignature_Rejected() public {
        bytes32 proposalId  = keccak256("prop-short");
        bytes32 actionsHash = keccak256("actions");
        _activateSigner(SIGNER);

        address[] memory signers = new address[](1);
        bytes[]   memory sigs    = new bytes[](1);
        signers[0] = SIGNER;
        sigs[0]    = new bytes(64); // must be exactly 65

        vm.prank(address(0));
        (uint256 validCount,) = auth.verifyAndConsume(proposalId, actionsHash, signers, sigs);
        assertEq(validCount, 0);
    }

    function test_Exploit_WrongProposalId_Rejected() public {
        bytes32 proposalId  = keccak256("real-prop");
        bytes32 actionsHash = keccak256("actions");
        _activateSigner(SIGNER);

        // Sign for "real-prop" but submit under "fake-prop"
        bytes memory sig = _sign(SIGNER_PK, _buildDigest(proposalId, actionsHash, SIGNER, 0));

        address[] memory signers = new address[](1);
        bytes[]   memory sigs    = new bytes[](1);
        signers[0] = SIGNER;
        sigs[0]    = sig;

        bytes32 fakeProposalId = keccak256("fake-prop");
        vm.prank(address(0));
        (uint256 validCount,) = auth.verifyAndConsume(fakeProposalId, actionsHash, signers, sigs);
        assertEq(validCount, 0);
    }

    function test_Exploit_InactiveSigner_Rejected() public {
        bytes32 proposalId  = keccak256("inactive-prop");
        bytes32 actionsHash = keccak256("actions");
        // _activateSigner NOT called — signer is inactive

        bytes memory sig = _sign(SIGNER_PK, _buildDigest(proposalId, actionsHash, SIGNER, 0));

        address[] memory signers = new address[](1);
        bytes[]   memory sigs    = new bytes[](1);
        signers[0] = SIGNER;
        sigs[0]    = sig;

        vm.prank(address(0));
        (uint256 validCount,) = auth.verifyAndConsume(proposalId, actionsHash, signers, sigs);
        assertEq(validCount, 0);
    }

    // ── D. Premature execution (delay out of range) ───────────────────────────

    function test_Exploit_BelowMinimumDelay_Reverts() public {
        vm.prank(address(0));
        vm.expectRevert(bytes4(keccak256("TL_DelayOutOfRange()")));
        tde.queue(keccak256("early-prop"), 1 days); // < 2 day minimum
    }

    function test_Exploit_AboveMaximumDelay_Reverts() public {
        vm.prank(address(0));
        vm.expectRevert(bytes4(keccak256("TL_DelayOutOfRange()")));
        tde.queue(keccak256("late-prop"), 31 days); // > 30 day maximum
    }

    function test_Exploit_ZeroDelay_Reverts() public {
        vm.prank(address(0));
        vm.expectRevert(bytes4(keccak256("TL_DelayOutOfRange()")));
        tde.queue(keccak256("zero-delay"), 0);
    }

    // ── E. Proposal replay ────────────────────────────────────────────────────

    function test_Exploit_SignatureReplay_SameProposal_Rejected() public {
        bytes32 proposalId  = keccak256("replay-prop");
        bytes32 actionsHash = keccak256("actions");
        _activateSigner(SIGNER);

        bytes memory sig = _sign(SIGNER_PK, _buildDigest(proposalId, actionsHash, SIGNER, 0));

        address[] memory signers = new address[](1);
        bytes[]   memory sigs    = new bytes[](1);
        signers[0] = SIGNER;
        sigs[0]    = sig;

        vm.prank(address(0));
        (uint256 count1,) = auth.verifyAndConsume(proposalId, actionsHash, signers, sigs);
        assertEq(count1, 1);

        // Second call with the same sig on the same proposal — _proposalApprovals blocks it
        vm.prank(address(0));
        (uint256 count2,) = auth.verifyAndConsume(proposalId, actionsHash, signers, sigs);
        assertEq(count2, 0);
    }

    function test_Exploit_TimelockReplay_AlreadyQueued_Reverts() public {
        bytes32 proposalId = keccak256("queued-replay");

        vm.prank(address(0));
        tde.queue(proposalId, 2 days);

        vm.prank(address(0));
        vm.expectRevert(bytes4(keccak256("TL_AlreadyQueued()")));
        tde.queue(proposalId, 2 days);
    }

    // ── F. Unauthorized access ────────────────────────────────────────────────

    function test_Exploit_UnauthorizedCoordinator_Auth_Reverts() public {
        bytes32 proposalId  = keccak256("unauth");
        bytes32 actionsHash = keccak256("actions");

        address[] memory signers = new address[](0);
        bytes[]   memory sigs    = new bytes[](0);

        vm.prank(address(0x1337));
        vm.expectRevert(Authorization.AL_OnlyCoordinator.selector);
        auth.verifyAndConsume(proposalId, actionsHash, signers, sigs);
    }

    function test_Exploit_UnauthorizedCoordinator_Timelock_Reverts() public {
        vm.prank(address(0x1337));
        vm.expectRevert(bytes4(keccak256("TL_OnlyCoordinator()")));
        tde.queue(keccak256("unauth-tl"), 2 days);
    }

    function test_Exploit_ArrayLengthMismatch_Reverts() public {
        bytes32 proposalId  = keccak256("mismatch");
        bytes32 actionsHash = keccak256("actions");

        address[] memory signers = new address[](2);
        bytes[]   memory sigs    = new bytes[](1); // length mismatch

        vm.prank(address(0));
        vm.expectRevert(Authorization.AL_ArrayLengthMismatch.selector);
        auth.verifyAndConsume(proposalId, actionsHash, signers, sigs);
    }

    // ── G. Execution guards ───────────────────────────────────────────────────

    function test_Exploit_ExecuteTransfer_InsufficientETH_Reverts() public {
        // treasury has 0 ETH, tries to send 1 ETH
        IAction.ProposalAction memory action = IAction.ProposalAction({
            actionType: IAction.ActionType.TRANSFER,
            target:     address(0),
            recipient:  address(0xDEAD),
            value:      0,
            amount:     1 ether,
            callData:   ""
        });

        vm.expectRevert(SecureTreasuryExecution.AT_InsufficientBalance.selector);
        treasury.executeTransfer(action, 0);
    }

    function test_Exploit_ExecuteCall_FailedCall_Reverts() public {
        // Calling a reverting contract → AT_ActionFailed
        address target = address(new Reverter());

        IAction.ProposalAction memory action = IAction.ProposalAction({
            actionType: IAction.ActionType.CALL,
            target:     target,
            recipient:  address(0),
            value:      0,
            amount:     0,
            callData:   abi.encodeWithSignature("fail()")
        });

        vm.expectRevert(
            abi.encodeWithSelector(SecureTreasuryExecution.AT_ActionFailed.selector, 0)
        );
        treasury.executeCall(action, 0);
    }

    // ── H. Invalid Merkle proof ───────────────────────────────────────────────

    function test_Exploit_InvalidMerkleProof_Reverts() public {
        address claimant = address(0xF00D);
        uint256 amount   = 1 ether;
        uint256 epochId  = 50;

        (bytes32 root,) = _buildMerkle(claimant, amount);
        _seedEpoch(epochId, root, address(0), 10 ether);
        vm.deal(address(rd), 10 ether);

        bytes32[] memory badProof = new bytes32[](1);
        badProof[0] = keccak256("garbage");

        vm.expectRevert(RewardDistributor.RD_InvalidProof.selector);
        rd.claim(epochId, claimant, amount, badProof);
    }

    function test_Exploit_ClaimNonexistentEpoch_Reverts() public {
        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert(RewardDistributor.RD_EpochNotFound.selector);
        rd.claim(9999, address(0xBEEF), 1 ether, proof);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Utility contracts
// ══════════════════════════════════════════════════════════════════════════════

contract ValueReceiver {
    receive() external payable {}
}

contract Reverter {
    function fail() external pure {
        revert("always reverts");
    }
}
