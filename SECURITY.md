Pause Guard
Any action is blocked instantly if govPrevention.isPaused() returns true. 
Acts as an emergency freezes the entire system before anything else runs.

Multi-Sig Authorization 
Actions require approval from multiple designated signers using EIP-712 signatures

Timelock
Even after approval, execution is locked behind a mandatory waiting period.

Drain Limit
Daily outflows are capped at a percentage of the treasury balance

Reward Distribution
flag set before transfer it also blocks reentrancy