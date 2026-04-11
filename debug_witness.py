#!/usr/bin/env python3
import sys
sys.path.insert(0, 'd:\\5thSem\\BCD\\forensic-blockchain\\backend')

import database as db

print("=== ALL USERS ===")
users = db.get_all_users()
for u in users:
    print(f"ID: {u['id']}, Name: {u['name']}, Email: {u['email']}, Role: {u['role']}")

print("\n=== EVIDENCE EV-E0AEB6B5 STATE ===")
ev = db.get_evidence_by_id('EV-E0AEB6B5')
if ev:
    print(f"Status: {ev.get('status')}")
    print(f"Witness Required ID: {ev.get('witness_required_id')}")
    print(f"Witness Signed By: {ev.get('witness_signed_by')}")
    print(f"TX Hash: {ev.get('tx_hash')}")
else:
    print("Evidence not found")
