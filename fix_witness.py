#!/usr/bin/env python3
import sys
sys.path.insert(0, 'd:\\5thSem\\BCD\\forensic-blockchain\\backend')

import database as db

print("Fixing evidence EV-E0AEB6B5 status to pending_witness...")
db.update_evidence_status('EV-E0AEB6B5', 'pending_witness')

ev = db.get_evidence_by_id('EV-E0AEB6B5')
print(f"Status after fix: {ev.get('status')}")
print(f"Witness: ID {ev.get('witness_required_id')} (johan)")
print("\nNow restart backend and have johan click Witness Sign.")
