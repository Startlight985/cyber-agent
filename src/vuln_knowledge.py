"""Solidity Vulnerability Knowledge Base for RAG.

Generic vulnerability patterns + attack strategies.
NOT level-specific answers — genuine reasoning augmentation.
"""

# ── Vulnerability Pattern Database ─────────────────────────────

VULN_PATTERNS: dict[str, dict] = {

    # ── Access Control ──────────────────────────────────────────

    "tx_origin_auth": {
        "category": "access_control",
        "name": "tx.origin Authentication Bypass",
        "description": "Using tx.origin for authentication instead of msg.sender. tx.origin is the original EOA that initiated the transaction, while msg.sender is the immediate caller. An attacker can trick the victim into calling a malicious contract that forwards the call.",
        "detection": ["tx.origin", "require(tx.origin =="],
        "attack_pattern": "Deploy intermediary contract. When victim calls your contract, your contract calls the target. tx.origin = victim, msg.sender = your contract.",
        "solidity_template": "interface ITarget { function sensitiveAction() external; } contract Attack { function exploit(address target) external { ITarget(target).sensitiveAction(); } }",
    },

    "unprotected_function": {
        "category": "access_control",
        "name": "Unprotected Sensitive Function",
        "description": "Functions that change critical state (owner, balances) without proper access control. Look for public/external functions missing onlyOwner or similar modifiers.",
        "detection": ["function.*public", "function.*external", "owner =", "admin ="],
        "attack_pattern": "Simply call the unprotected function directly.",
    },

    "constructor_typo": {
        "category": "access_control",
        "name": "Constructor Name Mismatch (Pre-0.4.22)",
        "description": "Before Solidity 0.4.22, constructors were functions with the same name as the contract. A typo makes it a regular public function anyone can call.",
        "detection": ["function.*public.*{", "Fal1out", "constructor"],
        "attack_pattern": "Call the misspelled 'constructor' function to claim ownership.",
    },

    # ── Delegatecall ────────────────────────────────────────────

    "delegatecall_storage_collision": {
        "category": "delegatecall",
        "name": "Delegatecall Storage Layout Collision",
        "description": "delegatecall executes external code in the caller's storage context. If the called contract writes to storage slot N, it modifies slot N in the CALLING contract. Attack: make the target delegatecall to YOUR contract whose storage layout maps slot N to a critical variable (like owner).",
        "detection": ["delegatecall", "library", "setTime", "setFirst"],
        "attack_pattern": "1) Deploy attack contract with SAME storage layout as target (match slot positions). 2) Your setTime/setX function writes attacker address to the slot that maps to 'owner' in the target. 3) Trick target into delegatecalling your contract. Key: storage slots must EXACTLY mirror the target's layout.",
        "solidity_template": "contract Attack { address public slot0; address public slot1; address public owner; function setTime(uint) public { owner = msg.sender; } }",
        "critical_notes": "In delegatecall context: msg.sender = original caller, msg.value = original value, but storage = caller's storage. The attack contract's code runs but reads/writes the TARGET's storage slots.",
    },

    "delegatecall_proxy_collision": {
        "category": "delegatecall",
        "name": "Proxy Storage Slot Collision",
        "description": "In proxy patterns, admin/implementation slots can collide with logic contract storage. EIP-1967 defines specific slots to avoid this, but custom proxies may have collisions.",
        "detection": ["proxy", "delegatecall", "admin", "implementation", "pendingAdmin"],
        "attack_pattern": "Find storage slots that overlap between proxy admin data and logic contract data. Write to one to modify the other. Example: if pendingAdmin slot = owner slot, calling proposeNewAdmin overwrites owner.",
    },

    # ── Reentrancy ──────────────────────────────────────────────

    "reentrancy_classic": {
        "category": "reentrancy",
        "name": "Classic Reentrancy (ETH Transfer)",
        "description": "External calls (call, send, transfer) to untrusted addresses before state updates. The callee can re-enter the function before balances are updated.",
        "detection": ["call{value", ".send(", ".transfer(", "withdraw"],
        "attack_pattern": "1) Deposit funds. 2) Call withdraw. 3) In receive()/fallback(), re-enter withdraw. Balance hasn't been updated yet, so the check passes again.",
        "solidity_template": "contract Attack { ITarget target; function attack() external payable { target.deposit{value: msg.value}(); target.withdraw(); } receive() external payable { if (address(target).balance >= amount) target.withdraw(); } }",
        "critical_notes": "Checks-Effects-Interactions pattern prevents this. ReentrancyGuard also works. But if only SOME functions have guards, cross-function reentrancy may still work.",
    },

    "reentrancy_cross_function": {
        "category": "reentrancy",
        "name": "Cross-Function Reentrancy",
        "description": "Reentering a DIFFERENT function that shares state with the vulnerable one. ReentrancyGuard on function A doesn't protect function B.",
        "detection": ["nonReentrant", "ReentrancyGuard", "multiple external functions sharing state"],
        "attack_pattern": "In the callback from function A, call function B which reads the not-yet-updated state.",
    },

    "reentrancy_erc721_callback": {
        "category": "reentrancy",
        "name": "ERC721/ERC1155 Callback Reentrancy",
        "description": "ERC721 safeTransferFrom and _safeMint call onERC721Received on the recipient. ERC1155 similarly calls onERC1155Received. These callbacks can re-enter.",
        "detection": ["_safeMint", "safeTransferFrom", "onERC721Received", "onERC1155Received", "checkOnERC721Received"],
        "attack_pattern": "Implement onERC721Received in your attack contract. When called during mint/transfer, re-enter to mint again or manipulate state. If balanceOf check happens AFTER the callback, you can bypass 'only one NFT' restrictions.",
    },

    "reentrancy_withdrawal": {
        "category": "reentrancy",
        "name": "Withdrawal Pattern Reentrancy",
        "description": "Pool/Vault withdrawAll functions that send ETH via call{value} without checking success. The callback can re-deposit or call other functions.",
        "detection": ["withdrawAll", "call{value", "payable(msg.sender).call"],
        "attack_pattern": "In receive() callback during withdrawal: re-deposit tokens, lock deposits, or call other functions that read stale state. The withdrawal function hasn't finished executing yet.",
    },

    # ── Integer/Arithmetic ──────────────────────────────────────

    "integer_overflow_underflow": {
        "category": "arithmetic",
        "name": "Integer Overflow/Underflow",
        "description": "In Solidity < 0.8.0, arithmetic wraps silently. uint256 underflow: 0-1 = 2^256-1. Overflow: max+1 = 0. Solidity >= 0.8.0 reverts on overflow by default unless unchecked{}.",
        "detection": ["pragma solidity ^0.6", "pragma solidity ^0.7", "unchecked", "transfer(", "balanceOf"],
        "attack_pattern": "Transfer more than your balance to underflow. Example: if you have 20 tokens, transfer 21. Result: 20-21 underflows to a huge number.",
    },

    "array_length_underflow": {
        "category": "arithmetic",
        "name": "Dynamic Array Length Underflow",
        "description": "In Solidity < 0.6.0, calling .length-- on an empty dynamic array underflows the length to 2^256-1, giving access to ALL storage slots.",
        "detection": ["codex", "retract", ".length", "array"],
        "attack_pattern": "1) Underflow array length via retract()/pop(). 2) Calculate which array index maps to the target storage slot. 3) Use array write (revise/push) to overwrite any storage slot including owner.",
    },

    # ── Randomness ──────────────────────────────────────────────

    "predictable_randomness": {
        "category": "randomness",
        "name": "Predictable On-Chain Randomness",
        "description": "Using block.number, block.timestamp, blockhash, or other on-chain data for randomness. Miners/validators can manipulate these, and other contracts can compute the same values.",
        "detection": ["block.number", "block.timestamp", "blockhash", "keccak256.*block", "coinFlip"],
        "attack_pattern": "Deploy a contract that computes the same 'random' value using the same block data, then calls the target with the known answer. Must be in the same block/transaction.",
        "solidity_template": "contract Attack { function predict(address target) external { uint256 factor = 57896044618658097711785492504343953926634992332820282019728792003956564819968; uint256 coinFlip = uint256(blockhash(block.number - 1)) / factor; ITarget(target).flip(coinFlip == 1); } }",
    },

    # ── ECDSA / Signatures ──────────────────────────────────────

    "ecdsa_malleability": {
        "category": "cryptography",
        "name": "ECDSA Signature Malleability",
        "description": "For any ECDSA signature (v, r, s), there exists another valid signature (v', r, n-s) where n is the secp256k1 curve order. Both recover to the same address. OpenZeppelin's ECDSA library (v4.1+) rejects s > n/2 to prevent this.",
        "detection": ["ecrecover", "ECDSA.recover", "signature", "v, r, s"],
        "attack_pattern": "Given (v, r, s): compute s' = n - s, v' = (v == 27 ? 28 : 27). The new signature (v', r, s') is valid for the same message. BUT: OZ ECDSA v4.1+ blocks high-s values. Only works with raw ecrecover or old OZ versions.",
        "critical_notes": "secp256k1 order n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141. If contract uses keccak256(signature) for uniqueness check but not the message hash, malleable signature bypasses the check.",
    },

    "ecrecover_return_zero": {
        "category": "cryptography",
        "name": "ecrecover Returns Zero Address",
        "description": "ecrecover returns address(0) for invalid signatures instead of reverting. If the contract doesn't check for address(0), anyone can pass an invalid signature to match a zero-initialized controller.",
        "detection": ["ecrecover", "controller", "address(0)"],
        "attack_pattern": "Pass an invalid signature (e.g., v=0, r=0, s=0) to ecrecover. It returns address(0). If the target variable (like controller) was never set or is address(0), the check passes.",
    },

    "signature_replay": {
        "category": "cryptography",
        "name": "Signature Replay Attack",
        "description": "Reusing a valid signature across different contexts — different chains, different contracts, or after state changes. Signatures should include chain ID, contract address, and nonce.",
        "detection": ["signature", "ecrecover", "ECDSA.recover", "nonce"],
        "attack_pattern": "If signature doesn't include nonce/chainId/contract address, replay it. If it uses keccak256(abi.encodePacked), look for hash collision via different inputs that produce same hash. If signatureUsed tracks keccak256(signature) not the message, use malleable signature.",
    },

    # ── EVM Specifics ───────────────────────────────────────────

    "storage_slot_reading": {
        "category": "evm",
        "name": "Reading Private Storage",
        "description": "'private' in Solidity only prevents other contracts from reading. Anyone can read ANY storage slot via eth_getStorageAt RPC call. Passwords, keys, and secrets stored in state variables are NOT private.",
        "detection": ["private", "password", "secret", "key", "bytes32"],
        "attack_pattern": "Use ethers.provider.getStorage(contractAddress, slotNumber) to read any slot. Variables are packed: slot 0 = first variable, slot 1 = second, etc. Mappings and arrays use keccak256-based slot calculation.",
    },

    "selfdestruct_force_eth": {
        "category": "evm",
        "name": "Force-Send ETH via selfdestruct",
        "description": "selfdestruct(address) sends all contract ETH to the target, bypassing receive()/fallback(). Cannot be blocked. NOTE: Post-Cancun (EIP-6780), selfdestruct only works in the same transaction as contract creation.",
        "detection": ["selfdestruct", "address(this).balance", "require.*balance"],
        "attack_pattern": "Deploy a contract with ETH, then selfdestruct(targetAddress) in the constructor. The target receives ETH regardless of its code. Post-Cancun: must selfdestruct in constructor (same tx as creation).",
        "solidity_template": "contract Force { constructor(address payable target) payable { selfdestruct(target); } }",
    },

    "extcodesize_zero": {
        "category": "evm",
        "name": "extcodesize == 0 During Construction",
        "description": "During contract construction, extcodesize(address) returns 0 because the code hasn't been deployed yet. This bypasses 'is not a contract' checks.",
        "detection": ["extcodesize", "isContract", "msg.sender.code.length"],
        "attack_pattern": "Put your attack logic in the constructor. During construction, code size = 0, so checks like 'require(!isContract(msg.sender))' pass.",
    },

    "gas_manipulation": {
        "category": "evm",
        "name": "Gas Manipulation for gasleft() Checks",
        "description": "gasleft() % N == 0 checks can be brute-forced by trying different gas amounts. Typically iterate with gas = i + (N * multiplier) until the check passes.",
        "detection": ["gasleft()", "% 8191", "gas"],
        "attack_pattern": "In a loop, call the target with varying gas amounts: for(i=0; i<300; i++) { target.call{gas: i + (8191*3)}(data); if(success) break; }",
    },

    "calldata_manipulation": {
        "category": "evm",
        "name": "Calldata Offset Manipulation",
        "description": "When a contract checks calldata at a fixed byte offset but uses dynamic offset for actual function dispatch, you can craft calldata that passes the check while calling a different function.",
        "detection": ["calldataload", "calldatacopy", "msg.data", "fixed offset"],
        "attack_pattern": "Craft raw calldata where: 1) The bytes at the checked offset satisfy the requirement. 2) The actual function selector + dynamic offset points to a different function. Use abi.encodePacked or manual hex construction.",
    },

    # ── ERC20 / Token ───────────────────────────────────────────

    "erc20_approve_bypass": {
        "category": "token",
        "name": "ERC20 approve/transferFrom Bypass",
        "description": "Token timelocks or restrictions on transfer() can be bypassed via approve() + transferFrom(). The restriction applies to direct transfers but not delegated transfers.",
        "detection": ["transfer", "transferFrom", "approve", "timelock", "lockTime"],
        "attack_pattern": "1) approve(yourself, balance). 2) transferFrom(self, recipient, balance). The timelock only checks transfer(), not transferFrom().",
    },

    "unchecked_return_value": {
        "category": "token",
        "name": "Unchecked External Call Return Value",
        "description": "Low-level calls (.call, .send) return a boolean success value. If not checked, failed transfers are silently ignored, leading to accounting mismatches.",
        "detection": [".call{value", ".send(", "(bool success,)", "= WETH.call("],
        "attack_pattern": "If a contract does StakeWETH without checking transferFrom return: 1) Approve max allowance but have 0 balance. 2) StakeWETH — transferFrom fails but returns false, contract ignores it, still credits your stake. 3) Unstake with inflated balance. If Unstake also ignores send failure: Unstake more than contract balance — send fails silently but accounting still debits.",
    },

    # ── DOS ──────────────────────────────────────────────────────

    "dos_revert": {
        "category": "dos",
        "name": "Denial of Service via Revert",
        "description": "A contract that must send ETH to an address can be blocked if that address reverts on receive. The 'King' pattern: become the recipient, then revert all incoming ETH.",
        "detection": ["transfer(", "send(", "king", "winner", "receive()"],
        "attack_pattern": "Deploy a contract with no receive/fallback (or one that reverts). Become the current recipient. Now no one can replace you because the transfer to your contract always reverts.",
        "solidity_template": "contract DOS { function attack(address payable target) external payable { target.call{value: msg.value}(''); } receive() external payable { revert(); } }",
    },

    "dos_gas_consumption": {
        "category": "dos",
        "name": "Gas Exhaustion Attack",
        "description": "Consume all available gas in a callback (receive/fallback) so the caller runs out of gas. Use while(true){} or assert(false) to burn gas.",
        "detection": ["partner", "call{value", "withdraw", "gas"],
        "attack_pattern": "Become the partner/recipient. In receive(), consume all gas: while(true){} or assert(false). The caller's remaining logic can't execute.",
    },

    # ── View/Interface ──────────────────────────────────────────

    "interface_spoof": {
        "category": "interface",
        "name": "Interface Implementation Spoofing",
        "description": "When a contract calls an external interface function, the implementation can return anything. If the caller trusts the return value, the implementation can lie.",
        "detection": ["interface", "external returns", "isLastFloor", "price()"],
        "attack_pattern": "Implement the required interface but return different values on different calls. Example: price() returns 100 on first call, 0 on second call. Or isLastFloor() returns false then true.",
        "solidity_template": "contract Spoof { uint count; function isLastFloor(uint) external returns (bool) { return count++ > 0; } }",
    },

    # ── Transient Storage / Advanced ────────────────────────────

    "transient_storage_exploit": {
        "category": "advanced",
        "name": "Transient Storage (EIP-1153) Exploitation",
        "description": "TSTORE/TLOAD provide storage that resets after each transaction. Contracts using transient storage for reentrancy locks or temporary state can have those bypassed across separate transactions or within callback contexts.",
        "detection": ["TransientSlot", "tstore", "tload", "transient"],
        "attack_pattern": "Transient storage resets per transaction. If a contract uses it for one-time-use flags, call in a new transaction. If used for reentrancy guard, it may not protect across cross-contract callbacks in the same tx.",
    },

    "create2_address_prediction": {
        "category": "advanced",
        "name": "CREATE2 Address Prediction / Contract Address Derivation",
        "description": "Contract addresses are deterministic. CREATE: keccak256(rlp([sender, nonce])). CREATE2: keccak256(0xff, sender, salt, keccak256(initCode)). Lost contract addresses can be recalculated.",
        "detection": ["recovery", "lost", "create2", "getCreateAddress"],
        "attack_pattern": "ethers.getCreateAddress({from: factoryAddress, nonce: N}) to find the lost contract address. Then interact with it directly.",
    },

    "minimal_bytecode": {
        "category": "advanced",
        "name": "Raw Bytecode Deployment",
        "description": "Some challenges require deploying contracts with specific runtime behavior using minimal bytecode. The EVM runtime code must return a specific value (e.g., 42) when called.",
        "detection": ["solver", "whatIsTheMeaningOfLife", "42", "10 opcodes"],
        "attack_pattern": "Creation code deploys runtime code. Runtime: PUSH 42, PUSH 0, MSTORE, PUSH 32, PUSH 0, RETURN. Creation: PUSH len, PUSH offset, PUSH 0, CODECOPY, PUSH len, PUSH 0, RETURN.",
    },

    "merkle_proof_manipulation": {
        "category": "advanced",
        "name": "Merkle Proof / State Proof Manipulation",
        "description": "L2 bridges and portals verify state inclusion via Merkle proofs. If the proof verification has ordering issues (executeMessage before verify), state can be manipulated during execution.",
        "detection": ["Merkle", "proof", "inclusion", "stateRoot", "executeMessage", "verifyInclusion"],
        "attack_pattern": "If executeMessage runs callbacks BEFORE verifying the proof, use the callback to modify state that the proof verification depends on. The verification passes against the modified state.",
    },

    "price_manipulation_dex": {
        "category": "defi",
        "name": "DEX Price Manipulation via Integer Division",
        "description": "DEX contracts that calculate swap prices using integer division are vulnerable to price manipulation. Each swap changes the token ratio, and repeated swaps in alternating directions amplify the imbalance until one token pool is drained.",
        "detection": ["swap", "getSwapPrice", "balanceOf", "transferFrom", "approve", "token1", "token2"],
        "attack_pattern": "Repeatedly swap token1→token2 then token2→token1. Integer division rounds down, creating a price drift. After ~6 swaps, you can drain one token entirely. Key: approve tokens to the DEX before swapping.",
    },

    "fake_token_injection": {
        "category": "defi",
        "name": "Fake Token / Unvalidated Token Address",
        "description": "DEX or swap contracts that don't validate token addresses can be exploited by creating a fake ERC20 token and swapping it for real tokens.",
        "detection": ["swap", "token", "transferFrom", "balanceOf", "from", "to"],
        "attack_pattern": "Deploy a fake ERC20 that returns any balanceOf. Use it to swap for real tokens in the DEX. The DEX doesn't verify the token is legitimate.",
        "solidity_template": "contract FakeToken { mapping(address=>uint) public balanceOf; function approve(address,uint) external returns(bool){return true;} function transferFrom(address,address,uint) external returns(bool){return true;} function mint(address to, uint a) external {balanceOf[to]+=a;} }",
    },

    "multicall_deposit_trick": {
        "category": "defi",
        "name": "Multicall Deposit Inflation",
        "description": "Contracts with multicall/batch functions that allow calling deposit() multiple times in one transaction, but msg.value is counted each time. This inflates the deposited amount without actually sending more ETH.",
        "detection": ["multicall", "deposit", "msg.value", "execute", "batch"],
        "attack_pattern": "Use multicall to call deposit() twice with the same msg.value. The contract counts the deposit twice but ETH is only sent once. Then drain the inflated balance.",
    },

    "custom_error_revert": {
        "category": "defi",
        "name": "Custom Error Exploitation in Try/Catch",
        "description": "Contracts using try/catch that handle specific custom errors can be exploited. By reverting with the expected error in a callback, you can trigger the catch block's special handling (e.g., sending entire balance instead of partial).",
        "detection": ["requestDonation", "notify", "NotEnoughBalance", "catch", "try"],
        "attack_pattern": "Deploy contract implementing the callback interface. In the callback, revert with the specific custom error the target catches. This triggers the catch block's fallback behavior.",
        "solidity_template": "contract Attack { error NotEnoughBalance(); function notify(uint256 amount) external { if (amount <= 10) revert NotEnoughBalance(); } }",
    },

    "type_confusion_calldata": {
        "category": "evm",
        "name": "Type Confusion via Raw Calldata",
        "description": "When a function parameter is a smaller type (uint8, uint16) but storage is uint256, raw calldata can pass a value larger than the type's max. The EVM doesn't enforce parameter types at the ABI level.",
        "detection": ["registerTreasury", "uint8", "uint256", "commander"],
        "attack_pattern": "Instead of calling the function normally (which truncates to uint8), send raw calldata with a uint256 value > 255. Use sendTransaction with manually encoded data: selector + padded value.",
    },

    "forta_detection_bot": {
        "category": "defi",
        "name": "Forta Detection Bot Registration",
        "description": "DoubleEntryPoint contracts with a Forta detection system. Register a detection bot that monitors delegateTransfer calls and raises alerts when the underlying token is being drained through the legacy token.",
        "detection": ["Forta", "delegateTransfer", "CryptoVault", "DoubleEntryPoint", "handleTransaction", "raiseAlert"],
        "attack_pattern": "Deploy a detection bot contract implementing IDetectionBot. In handleTransaction(), decode the calldata to check if origSender is the CryptoVault. If so, call raiseAlert(). Register the bot with the Forta contract.",
    },

    "bit_packing_overflow": {
        "category": "advanced",
        "name": "Bit Packing / Masking Overflow",
        "description": "When multiple values are packed into a single uint256 using bit shifts and masks, incorrect shift amounts or mask sizes can cause data to overlap or overflow into adjacent fields.",
        "detection": ["<<", ">>", "& mask", "uint80", "uint160", "uint16", "MASK"],
        "attack_pattern": "Analyze the exact bit layout. If encoding shifts by wrong amount (e.g., << 160 instead of << 176), data bleeds into adjacent fields. Craft input that exploits the overlap to overwrite critical fields like owner or nextId.",
    },
}


def search_patterns(query: str, top_k: int = 5) -> list[dict]:
    """Search vulnerability patterns by keyword matching."""
    query_lower = query.lower()
    scored = []
    for key, pattern in VULN_PATTERNS.items():
        score = 0
        # Match against name, description, category
        if query_lower in pattern["name"].lower():
            score += 10
        if query_lower in pattern["category"]:
            score += 5
        if query_lower in pattern.get("description", "").lower():
            score += 3
        # Match detection keywords
        for det in pattern.get("detection", []):
            if det.lower() in query_lower or query_lower in det.lower():
                score += 8
        if score > 0:
            scored.append((score, key, pattern))

    scored.sort(key=lambda x: -x[0])
    return [{"key": k, **p} for _, k, p in scored[:top_k]]


def match_source_code(source: str, top_k: int = 2, min_score: int = 10) -> list[dict]:
    """Match vulnerability patterns against contract source code. Only return high-confidence matches."""
    source_lower = source.lower()
    scored = []
    for key, pattern in VULN_PATTERNS.items():
        score = 0
        for det in pattern.get("detection", []):
            if det.lower() in source_lower:
                score += 5
        if score >= min_score:  # Only high-confidence matches
            scored.append((score, key, pattern))

    scored.sort(key=lambda x: -x[0])
    return [{"key": k, "match_score": s, **p} for s, k, p in scored[:top_k]]


def get_pattern(key: str) -> dict | None:
    """Get a specific vulnerability pattern by key."""
    return VULN_PATTERNS.get(key)


def get_attack_context(source: str) -> str:
    """Generate attack context string for LLM prompt augmentation."""
    matches = match_source_code(source, top_k=3)
    if not matches:
        return ""

    parts = ["## Relevant Vulnerability Patterns (from knowledge base)"]
    for m in matches:
        parts.append(f"\n### {m['name']} ({m['category']})")
        parts.append(m.get("description", ""))
        if "attack_pattern" in m:
            parts.append(f"**Attack strategy:** {m['attack_pattern']}")
        if "solidity_template" in m:
            parts.append(f"**Template:** ```{m['solidity_template']}```")
        if "critical_notes" in m:
            parts.append(f"**Critical:** {m['critical_notes']}")

    return "\n".join(parts)
