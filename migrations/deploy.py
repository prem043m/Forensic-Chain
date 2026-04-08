"""
deploy.py — Compile and deploy Evidence.sol to Ganache local testnet.

Usage:
    python deploy.py

Requirements:
    pip install py-solc-x web3

This script:
  1. Installs solc 0.8.0 if not present
  2. Compiles contracts/Evidence.sol
  3. Deploys to Ganache (http://127.0.0.1:7545)
  4. Saves contract address to backend/contract_address.txt
  5. Saves ABI to contracts/Evidence_abi.json
"""

import json
import os
import sys

try:
    import solcx
    from web3 import Web3
except ImportError as exc:
    print(f"ERROR: Missing dependency: {exc}")
    print("Run: python -m pip install py-solc-x web3")
    sys.exit(1)

# Handle middleware import across web3.py versions.
try:
    from web3.middleware import geth_poa_middleware
except ImportError:
    try:
        from web3.middleware import ExtraDataToPOAMiddleware
        geth_poa_middleware = ExtraDataToPOAMiddleware()
    except ImportError:
        geth_poa_middleware = None

GANACHE_URL = os.environ.get("GANACHE_URL", "http://127.0.0.1:7545")
# Resolve paths from project root (one level above migrations/)
ROOT_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOL_FILE    = os.path.join(ROOT_DIR, "contracts", "Evidence.sol")
ADDR_FILE   = os.path.join(ROOT_DIR, "backend", "contract_address.txt")
ABI_FILE    = os.path.join(ROOT_DIR, "contracts", "Evidence_abi.json")


def main():
    print("=" * 55)
    print("  ForensicChain — Contract Deployment Script")
    print("=" * 55)

    # 1. Connect to Ganache
    print(f"\n[1/4] Connecting to Ganache at {GANACHE_URL}...")
    w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    if geth_poa_middleware is not None:
        try:
            w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        except Exception as exc:
            print(f"  Warning: Could not inject POA middleware: {exc}. Continuing.")

    if not w3.is_connected():
        print("ERROR: Cannot connect to Ganache.")
        print("  Make sure Ganache is running on port 7545.")
        print("  Install Ganache: https://trufflesuite.com/ganache/")
        sys.exit(1)

    account = w3.eth.accounts[0]
    balance = w3.eth.get_balance(account)
    print(f"  Connected! Block #{w3.eth.block_number}")
    print(f"  Using account: {account}")
    print(f"  Balance: {w3.from_wei(balance, 'ether'):.2f} ETH")

    # 2. Compile contract
    print("\n[2/4] Compiling Evidence.sol...")
    solcx.install_solc("0.8.0", show_progress=False)
    solcx.set_solc_version("0.8.0")

    with open(SOL_FILE) as f:
        source = f.read()

    compiled = solcx.compile_source(source, output_values=["abi", "bin"])
    contract_id = [k for k in compiled.keys() if "EvidenceManagement" in k][0]
    abi      = compiled[contract_id]["abi"]
    bytecode = compiled[contract_id]["bin"]
    print(f"  Compiled successfully. Bytecode size: {len(bytecode)//2} bytes")

    # 3. Deploy
    print("\n[3/4] Deploying contract...")
    contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash  = contract.constructor().transact({"from": account, "gas": 3_000_000})
    receipt  = w3.eth.wait_for_transaction_receipt(tx_hash)
    address  = receipt.contractAddress
    gas_used = receipt.gasUsed
    print(f"  Deployed at: {address}")
    print(f"  TX hash:     {tx_hash.hex()}")
    print(f"  Gas used:    {gas_used:,}")

    # 4. Save artifacts
    print("\n[4/4] Saving artifacts...")
    with open(ADDR_FILE, "w") as f:
        f.write(address)
    print(f"  Contract address → {ADDR_FILE}")

    with open(ABI_FILE, "w") as f:
        json.dump(abi, f, indent=2)
    print(f"  ABI → {ABI_FILE}")

    print("\n" + "=" * 55)
    print("  Deployment complete!")
    print(f"  Contract Address: {address}")
    print("  You can now start the backend: python backend/app.py")
    print("=" * 55)


if __name__ == "__main__":
    main()
