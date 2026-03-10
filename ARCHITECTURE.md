Secure Treasury Execution System
Funds can only be moved if a proposal successfully passes multilevel approval, timelock delay , drain limit.so that funds cannot move unless several independent security checks pass base on requirement.


SecureTreasuryExecution
Anyone can submit a proposal for actions like token transfers, contract calls, or upgrades.
If the system is paused, new proposals are blocked.

Authorization
Designated signers must approve proposals using EIP-712 signatures.

Each signature uses a unique nonce to prevent replay attacks.
Each signer can approve a proposal only once, preventing double voting.

TimeDelayEngine
After approval, proposals must wait 2–30 days before execution.
This delay gives time for the community or security team to detect and cancel malicious actions.

GovernanceAttack
Even if other layers fail, daily withdrawal limits restrict how much can be moved from the treasury, preventing a full drain in a single event.

RewardDistributor
Handles reward payouts using Merkle proofs.
An off-chain system calculates rewards, posts a Merkle root on-chain, and users claim their share with a proof. Claims are tracked to prevent double spending.