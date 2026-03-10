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


contract MockAction {
    function propose(address, IAction.ProposalAction[] calldata, uint256)
        external pure returns (bytes32) { return keccak256("proposal-1"); }
}

contract MockGov {
    bool public paused;
    function isPaused() external view returns (bool) { return paused; }
    function setPaused(bool v) external { paused = v; }
}

contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; }
    function transfer(address to, uint256 amt) external returns (bool) {
        balanceOf[msg.sender] -= amt; balanceOf[to] += amt; return true;
    }
}

contract Attacker {
    RewardDistributor rd;
    bool public hit;
    constructor(address _rd) { rd = RewardDistributor(_rd); }
    function attack(uint256 epochId, uint256 amt, bytes32[] calldata proof) external {
        rd.claim(epochId, address(this), amt, proof);
    }
    receive() external payable {
        if (!hit) { hit = true; try rd.claim(0, address(this), 0, new bytes32[](0)) {} catch {} }
    }
}

contract TreasuryHarness is SecureTreasuryExecution {
    constructor(address am) SecureTreasuryExecution(am) {}
    function doTransfer(IAction.ProposalAction memory a, uint256 idx) external { _executeTransfer(a, idx); }
    function doCall   (IAction.ProposalAction memory a, uint256 idx) external { _executeCall(a, idx); }
}

contract Reverter { function fail() external pure { revert("nope"); } }
contract Sink     { receive() external payable {} }


contract SecureSystemTest is Test {

    uint256 constant SIGNER_PK   = 0xA11CE;
    uint256 constant ATTACKER_PK = 0xBAD;

    Authorization     auth;
    TimeDelayEngine   tde;
    RewardDistributor rd;
    TreasuryHarness   treasury;
    MockAction        mockAction;
    MockGov           mockGov;
    MockERC20         token;

    address SIGNER;

    function setUp() public {
        SIGNER     = vm.addr(SIGNER_PK);
        auth       = new Authorization();
        tde        = new TimeDelayEngine();
        rd         = new RewardDistributor();
        token      = new MockERC20();
        mockAction = new MockAction();
        mockGov    = new MockGov();
        treasury   = new TreasuryHarness(address(mockAction));

        vm.store(address(treasury), bytes32(0), bytes32(uint256(uint160(address(mockGov)))));
    }

    
    function _activate(address s) internal {
        vm.store(address(auth), keccak256(abi.encode(s, uint256(0))), bytes32(uint256(1)));
    }

    
    function _digest(bytes32 pid, bytes32 ah, address s, uint256 nonce)
        internal view returns (bytes32)
    {
        bytes32 th = keccak256(
            "ProposalApproval(bytes32 proposalId,bytes32 actionsHash,"
            "address signer,uint256 signerNonce,uint256 chainId)"
        );
        bytes32 sh = keccak256(abi.encode(th, pid, ah, s, nonce, block.chainid));
        return keccak256(abi.encodePacked("\x19\x01", bytes32(0), sh));
    }

    function _sig(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    function _verify(bytes32 pid, bytes32 ah, address signer, bytes memory sig)
        internal returns (uint256 validCount)
    {
        address[] memory ss = new address[](1); ss[0] = signer;
        bytes[]   memory gs = new bytes[](1);   gs[0] = sig;
        vm.prank(address(0));
        (validCount,) = auth.verifyAndConsume(pid, ah, ss, gs);
    }

    function _merkle(address recipient, uint256 amt)
        internal pure returns (bytes32 root, bytes32[] memory proof)
    {
        bytes32 l0 = MerkleLib.computeLeaf(recipient, amt);
        bytes32 l1 = MerkleLib.computeLeaf(address(0xdead), 1);
        (bytes32 lo, bytes32 hi) = l0 < l1 ? (l0, l1) : (l1, l0);
        root = keccak256(abi.encodePacked(lo, hi));
        proof = new bytes32[](1); proof[0] = l1;
    }

    function _epoch(uint256 id, bytes32 root, address tok, uint256 total) internal {
        bytes32 b = keccak256(abi.encode(id, uint256(1)));
        vm.store(address(rd), bytes32(uint256(b)),     root);
        vm.store(address(rd), bytes32(uint256(b) + 1), bytes32(uint256(uint160(tok))));
        vm.store(address(rd), bytes32(uint256(b) + 2), bytes32(total));
        vm.store(address(rd), bytes32(uint256(b) + 4), bytes32(uint256(1))); // createdAt
    }

    function _transferAction(address target, address recipient, uint256 amt)
        internal pure returns (IAction.ProposalAction memory)
    {
        return IAction.ProposalAction(IAction.ActionType.TRANSFER, target, recipient, 0, amt, "");
    }

   
    function test_Propose_ReturnsId() public {
        IAction.ProposalAction[] memory acts = new IAction.ProposalAction[](0);
        bytes32 id = treasury.propose(acts, 3 days);
        assertEq(id, keccak256("proposal-1"));
    }



    function test_Sig_Valid() public {
        bytes32 pid = keccak256("p1"); bytes32 ah = keccak256("a1");
        _activate(SIGNER);
        uint256 count = _verify(pid, ah, SIGNER, _sig(SIGNER_PK, _digest(pid, ah, SIGNER, 0)));
        assertEq(count, 1);
    }

    function test_Sig_NonceIncrementsAfterUse() public {
        bytes32 pid = keccak256("p1"); bytes32 ah = keccak256("a1");
        _activate(SIGNER);
        _verify(pid, ah, SIGNER, _sig(SIGNER_PK, _digest(pid, ah, SIGNER, 0)));

        bytes32 pid2 = keccak256("p2");
        uint256 count = _verify(pid2, ah, SIGNER, _sig(SIGNER_PK, _digest(pid2, ah, SIGNER, 0)));
        assertEq(count, 0);
    }

    function test_Timelock_EtaCorrect() public {
        vm.warp(1_000_000);
        vm.prank(address(0));
        uint256 eta = tde.queue(keccak256("q1"), 5 days);
        assertEq(eta, 1_000_000 + 5 days);
    }

    function test_Timelock_MinAndMaxBoundary() public {
        vm.prank(address(0)); tde.queue(keccak256("min"), 2 days);
        vm.prank(address(0)); tde.queue(keccak256("max"), 30 days);
    }

    function test_Claim_ETH() public {
        address payable alice = payable(address(0xA1));
        (bytes32 root, bytes32[] memory proof) = _merkle(alice, 1 ether);
        _epoch(1, root, address(0), 10 ether);
        vm.deal(address(rd), 10 ether);

        rd.claim(1, alice, 1 ether, proof);
        assertEq(alice.balance, 1 ether);
    }

    
    function test_Exploit_Reentrancy() public {
        Attacker attacker = new Attacker(address(rd));
        (bytes32 root, bytes32[] memory proof) = _merkle(address(attacker), 1 ether);
        _epoch(10, root, address(0), 5 ether);
        vm.deal(address(rd), 5 ether);

        attacker.attack(10, 1 ether, proof);

        assertEq(address(rd).balance, 4 ether); 
        assertTrue(attacker.hit());             
    }

    function test_Exploit_DoubleClaim() public {
        address alice = address(0xA1);
        (bytes32 root, bytes32[] memory proof) = _merkle(alice, 1 ether);
        _epoch(20, root, address(0), 5 ether);
        vm.deal(address(rd), 5 ether);

        rd.claim(20, alice, 1 ether, proof);

        vm.expectRevert(RewardDistributor.RD_AlreadyClaimed.selector);
        rd.claim(20, alice, 1 ether, proof);
    }

    function test_Exploit_WrongKey() public {
        bytes32 pid = keccak256("evil"); bytes32 ah = keccak256("data");
        _activate(SIGNER);
        uint256 count = _verify(pid, ah, SIGNER, _sig(ATTACKER_PK, _digest(pid, ah, SIGNER, 0)));
        assertEq(count, 0);
    }


    function test_Exploit_SignatureReplay() public {
        bytes32 pid = keccak256("replay"); bytes32 ah = keccak256("data");
        _activate(SIGNER);
        bytes memory sig = _sig(SIGNER_PK, _digest(pid, ah, SIGNER, 0));

        assertEq(_verify(pid, ah, SIGNER, sig), 1); // first: accepted
        assertEq(_verify(pid, ah, SIGNER, sig), 0); // replay: rejected
    }

    function test_Exploit_TimelockReplay() public {
        bytes32 id = keccak256("queued-twice");
        vm.prank(address(0)); tde.queue(id, 2 days);

        vm.prank(address(0));
        vm.expectRevert(bytes4(keccak256("TL_AlreadyQueued()")));
        tde.queue(id, 2 days);
    }

    function test_Exploit_UnauthorizedAuth() public {
        address[] memory ss = new address[](0);
        bytes[]   memory gs = new bytes[](0);
        vm.prank(address(0x1337));
        vm.expectRevert(Authorization.AL_OnlyCoordinator.selector);
        auth.verifyAndConsume(bytes32(0), bytes32(0), ss, gs);
    }

    function test_Exploit_UnauthorizedTimelock() public {
        vm.prank(address(0x1337));
        vm.expectRevert(bytes4(keccak256("TL_OnlyCoordinator()")));
        tde.queue(keccak256("x"), 2 days);
    }

    function test_Exploit_InsufficientETH() public {
        vm.expectRevert(SecureTreasuryExecution.AT_InsufficientBalance.selector);
        treasury.doTransfer(_transferAction(address(0), address(0xDEAD), 1 ether), 0);
    }

    function test_Exploit_InvalidProof() public {
        address alice = address(0xA1);
        (bytes32 root,) = _merkle(alice, 1 ether);
        _epoch(50, root, address(0), 5 ether);
        vm.deal(address(rd), 5 ether);

        bytes32[] memory bad = new bytes32[](1); bad[0] = keccak256("garbage");
        vm.expectRevert(RewardDistributor.RD_InvalidProof.selector);
        rd.claim(50, alice, 1 ether, bad);
    }
}
