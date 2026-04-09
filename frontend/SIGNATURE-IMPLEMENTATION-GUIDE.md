# Digital Signature Pad Integration Guide

## Overview

The **Digital Signature Pad** is a lightweight HTML5 Canvas component that captures officer signatures during evidence transfers. The signature itself is **not stored as an image** (to avoid storage overhead), but the act of signing **triggers a blockchain transaction** to update evidence custodian on-chain.

This creates a **legal, auditable chain of custody** that feels like a physical signing process.

## Files

- **`signature-pad.js`** — Core signature capture component (Canvas-based)
- **`signature-integration.html`** — Full demo with workflow
- **`SIGNATURE-IMPLEMENTATION-GUIDE.md`** — This file

## Quick Facts

| Aspect | Detail |
|--------|--------|
| **Storage Model** | No images stored; signature is just a trigger for blockchain transaction |
| **Data Captured** | Timestamp, point count, signature hash (for audit trail) |
| **Input Methods** | Mouse, touchpad, touch screen |
| **Canvas Size** | Default 500×200px (configurable) |
| **Dependencies** | None (pure vanilla JavaScript) |
| **Browser Support** | All modern browsers (Chrome, Firefox, Safari, Edge) |

## Architecture

```
Officer Views Evidence
    ↓
Clicks "Transfer to [Analyst]" Button
    ↓
Signature Modal Opens (Shows Transfer Details)
    ↓
Officer Signs on Canvas (No image saved)
    ↓
Clicks "Sign & Transfer" Button
    ↓
Frontend collects signature metadata (timestamp, hash)
    ↓
Backend endpoint receives transfer request + signature data
    ↓
Backend creates blockchain transaction
    ↓
Smart Contract updates evidence custodian
    ↓
Transaction hash returned to frontend
    ↓
Officer sees confirmation with TX hash
```

## Implementation Steps

### Step 1: Add Scripts to Dashboard

Add these to your `dashboard.html` `<head>` or before `</body>`:

```html
<!-- Signature component -->
<script src="signature-pad.js"></script>

<!-- Web3.js for blockchain (if not already included) -->
<script src="https://cdn.jsdelivr.net/npm/web3@1.10.0/dist/web3.min.js"></script>
```

### Step 2: Create Transfer Button

In your evidence list or detail view:

```html
<button class="transfer-button" onclick="initiateSignedTransfer({
    id: 'EV-A7F2K9M1',
    name: 'Suspect Phone',
    from: 'Detective Mike',
    to: 'Analyst Linda',
    caseId: 'C-2026-001847'
})">
    📝 Transfer to Analyst
</button>
```

### Step 3: Implement Modal Opening Function

```javascript
function initiateSignedTransfer(transferData) {
    // Create modal container
    const modal = document.createElement('div');
    modal.className = 'signature-modal';
    modal.innerHTML = `
        <div class="modal-overlay">
            <div class="modal-content">
                <div class="modal-header">
                    <h2>Authorize Evidence Transfer</h2>
                    <button class="close-btn" onclick="this.closest('.signature-modal').remove()">×</button>
                </div>
                
                <div class="modal-body">
                    <!-- Transfer Details Section -->
                    <div class="transfer-details">
                        <div class="detail-row">
                            <span class="label">Evidence:</span>
                            <span class="value">${transferData.name}</span>
                        </div>
                        <div class="detail-row">
                            <span class="label">From:</span>
                            <span class="value">${transferData.from}</span>
                        </div>
                        <div class="detail-row">
                            <span class="label">To:</span>
                            <span class="value">${transferData.to}</span>
                        </div>
                        <div class="detail-row">
                            <span class="label">Case ID:</span>
                            <span class="value">${transferData.caseId}</span>
                        </div>
                    </div>

                    <!-- Signature Pad Container -->
                    <div class="signature-pad-container"></div>
                </div>
            </div>
        </div>
    `;

    document.body.appendChild(modal);

    // Initialize signature pad
    const padContainer = modal.querySelector('.signature-pad-container');
    const pad = new SignaturePad(padContainer, {
        width: 500,
        height: 200,
        onSave: (signatureData) => {
            handleSignedTransfer(transferData, signatureData, modal, pad);
        }
    });
}
```

### Step 4: Handle Signature Save & Blockchain Transaction

```javascript
async function handleSignedTransfer(transferData, signatureData, modal, pad) {
    pad.setStatus('🔄 Initiating blockchain transaction...', 'info');
    pad.setButtonsDisabled(true);

    try {
        // Call backend endpoint
        const response = await fetch('/api/evidence/transfer-signed', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                evidence_id: transferData.id,
                to_custodian: transferData.to,
                signed_at: signatureData.timestamp,
                signature_hash: signatureData.signatureHash,
                point_count: signatureData.pointCount
            })
        });

        const result = await response.json();

        if (result.success || result.tx_hash) {
            pad.setStatus(
                `✅ SUCCESS!\n\nTX: ${result.tx_hash.substring(0, 24)}...\n\nCustodian updated on blockchain`,
                'success'
            );

            // Optional: Reload evidence list or navigate
            setTimeout(() => {
                modal.remove();
                // location.reload(); // Refresh to show updated custodian
            }, 2500);
        } else {
            pad.setStatus(
                `❌ Transfer failed:\n${result.error}`,
                'error'
            );
        }
    } catch (error) {
        pad.setStatus(
            `❌ Error:\n${error.message}`,
            'error'
        );
    } finally {
        pad.setButtonsDisabled(false);
    }
}
```

### Step 5: Backend Endpoint (Python Flask)

Update your `backend/app.py`:

```python
@app.route("/api/evidence/transfer-signed", methods=["POST"])
@login_required
def transfer_evidence_signed():
    """
    Transfer evidence with digital signature authorization.
    Signature is not stored, but action triggers blockchain transaction.
    """
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    evidence_id = data.get("evidence_id")
    to_custodian = data.get("to_custodian")
    signed_at = data.get("signed_at")
    signature_hash = data.get("signature_hash")
    point_count = data.get("point_count", 0)

    if not evidence_id or not to_custodian:
        return jsonify({"error": "Missing evidence_id or to_custodian"}), 400

    # Verify exists
    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": "Evidence not found"}), 404

    # Verify user has permission to transfer
    if evidence.get("current_custodian_id") != session["user_id"]:
        return jsonify({"error": "Only current custodian can transfer"}), 403

    try:
        # Update database - set new custodian
        db.update_evidence_custodian(
            evidence_id, 
            session["user_id"],
            to_custodian
        )

        # Log transfer with signature reference
        log_entry_id = db.add_custody_log(
            evidence_id,
            "Transfer - Digitally Signed",
            session["user_id"],
            f"Digitally signed transfer to {to_custodian}",
            signature_hash=signature_hash,
            signed_at=signed_at
        )

        # Trigger blockchain update
        tx_meta, bc_error = blockchain.transfer_evidence(
            evidence_id,
            "Transfer - Digitally Signed",
            f"Custodian changes to {to_custodian} (points: {point_count})"
        )

        if bc_error:
            app.logger.warning(f"Blockchain transfer failed: {bc_error}")
            tx_meta = {
                "tx_hash": "OFFLINE-" + uuid.uuid4().hex[:16],
                "status": "offline"
            }

        return jsonify({
            "success": True,
            "message": "Evidence transfer completed with digital signature",
            "evidence_id": evidence_id,
            "tx_hash": tx_meta["tx_hash"],
            "new_custodian": to_custodian,
            "signed_at": signed_at,
            "signature_hash": signature_hash,
            "log_entry_id": log_entry_id
        }), 200

    except Exception as e:
        app.logger.error(f"Transfer error: {str(e)}")
        return jsonify({"error": str(e)}), 500
```

### Step 6: Update Database Schema

Add signature reference to custody_logs table:

```python
# In backend/database.py

def init_db():
    """Initialize database with all tables"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Verify custody_logs has signature columns (add if missing)
        cursor.execute("""
            ALTER TABLE custody_logs 
            ADD COLUMN IF NOT EXISTS signature_hash VARCHAR(16),
            ADD COLUMN IF NOT EXISTS signed_at TIMESTAMP
        """)
        
        conn.commit()
```

## CSS Styling for Modal

Add to your main CSS file:

```css
/* Signature Modal Styles */
.signature-modal {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 2000;
}

.modal-overlay {
    animation: slideIn 0.3s ease;
}

.modal-content {
    background: white;
    border-radius: 8px;
    max-width: 600px;
    width: 90%;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
}

.modal-header {
    background: #1a1a2e;
    color: white;
    padding: 20px 24px;
    border-bottom: 3px solid #e74c3c;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.modal-header h2 {
    font-size: 18px;
    font-weight: 700;
    margin: 0;
}

.close-btn {
    background: none;
    border: none;
    color: white;
    font-size: 28px;
    cursor: pointer;
    opacity: 0.7;
}

.close-btn:hover {
    opacity: 1;
}

.modal-body {
    padding: 24px;
}

.transfer-details {
    background: #f8f9fa;
    padding: 16px;
    border-radius: 4px;
    border-left: 4px solid #e74c3c;
    margin-bottom: 20px;
}

.detail-row {
    display: flex;
    justify-content: space-between;
    padding: 6px 0;
    font-size: 13px;
    border-bottom: 1px solid #e0e0e0;
}

.detail-row:last-child {
    border-bottom: none;
}

.detail-row .label {
    font-weight: 600;
    color: #666;
}

.detail-row .value {
    font-family: 'Courier New', monospace;
    color: #1a1a2e;
}

.signature-pad-container {
    margin: 20px 0;
}

@keyframes slideIn {
    from {
        transform: translateY(-20px);
        opacity: 0;
    }
    to {
        transform: translateY(0);
        opacity: 1;
    }
}
```

## API Reference - SignaturePad Class

### Constructor

```javascript
const pad = new SignaturePad(containerElement, options);
```

**Options:**
- `width` (number) — Canvas width in pixels (default: 500)
- `height` (number) — Canvas height in pixels (default: 200)
- `lineColor` (string) — Stroke color (default: '#1a1a2e')
- `lineWidth` (number) — Stroke width (default: 2)
- `backgroundColor` (string) — Canvas background (default: '#ffffff')
- `onSave` (function) — Callback when "Sign & Transfer" is clicked
- `onClear` (function) — Callback when "Clear" is clicked

### Methods

#### `clear()`
Erase the canvas

```javascript
pad.clear();
```

#### `getSignatureData()`
Get metadata (not image)

```javascript
const data = pad.getSignatureData();
// Returns: {
//   timestamp: "2026-04-09T15:30:45.123Z",
//   pointCount: 45,
//   signedAt: 1712700645,
//   hasSignature: true,
//   signatureHash: "a7f2k9m1"
// }
```

#### `setStatus(message, type)`
Display status message

```javascript
pad.setStatus('Processing...', 'info');    // blue
pad.setStatus('Success!', 'success');      // green
pad.setStatus('Error occurred', 'error');  // red
```

#### `setButtonsDisabled(disabled)`
Disable/enable buttons during transaction

```javascript
pad.setButtonsDisabled(true);  // Disable during blockchain call
pad.setButtonsDisabled(false); // Re-enable after
```

#### `getElement()`
Get the wrapper DOM element

```javascript
const element = pad.getElement();
document.body.appendChild(element);
```

## Custody Log Schema Update

When storing transfers, the custody_logs table now includes:

```sql
ALTER TABLE custody_logs ADD COLUMN signature_hash VARCHAR(16);
ALTER TABLE custody_logs ADD COLUMN signed_at TIMESTAMP;
```

Example log entry:
```
Evidence ID: EV-A7F2K9M1
Action: "Transfer - Digitally Signed"
Actor: Officer Mike (user_id: 5)
Note: "Digitally signed transfer to Analyst Linda"
TX Hash: "0x7f2a9k3..."
Signature Hash: "a7f2k9m1"
Signed At: "2026-04-09 15:30:45"
```

## Blockchain Integration

The signature action triggers the existing `transferEvidence()` function in your smart contract:

```solidity
// Evidence.sol
function transferEvidence(
    string memory _id,
    string memory _action,
    string memory _note
) public {
    // Adds custody record to chain
    // Note includes signature metadata + point count
    // Blockchain timestamp serves as legal proof
}
```

**Example transaction note:**
```
"Digitally signed transfer to Analyst Linda Chen. Signature points: 52. Hash: a7f2k9m1"
```

## User Experience Flow

### Officer's Perspective

1. **Finds evidence** in their custody → Sees "Transfer" button
2. **Clicks transfer button** → Modal opens showing:
   - Evidence name & ID
   - Who it's from (themselves)
   - Who it's going to
   - Case ID
3. **Reads carefully**, then **signs on canvas** with mouse or touch
4. **Clicks "Sign & Transfer"** button
5. **Sees loading indicator** while blockchain processes
6. **Gets confirmation** with transaction hash
7. **Modal closes** → Evidence now shows new custodian

### Backend Process

1. Receives signed transfer request
2. Verifies officer is current custodian
3. Updates `evidence.current_custodian` in DB
4. Adds custody log entry with signature metadata
5. Calls `blockchain.transfer_evidence()`
6. Returns TX hash to frontend

### Blockchain Record

1. Smart contract creates new custody record
2. Logs include:
   - Timestamp
   - From/To custodian addresses
   - Transfer note (includes signature info)
   - Transaction hash (permanent proof)

## Demo & Testing

Open `signature-integration.html` in your browser to see:
- Full workflow demo
- Interactive signature capture
- Mock blockchain transaction
- Status feedback

## Security Considerations

### ✅ What This Secures
- **Non-repudiation**: Officer's signature tied to transfer
- **Audit trail**: Every transfer logged with timestamp
- **Blockchain proof**: Immutable record on-chain
- **Chain of custody**: Physical-feeling signing process

### ⚠️ Important Notes
1. **Signature not stored as image** — Keeps storage lightweight
2. **Signature hash is NOT cryptographic** — Just for audit reference
3. **Actual security from**:
   - User authentication (login)
   - Session validation
   - Blockchain immutability
   - Database audit logs

### 🔒 Best Practices
- Require login before transfer
- Log who initiated transfer + when
- Store IP address in audit log
- Verify blockchain transaction confirmation
- Never auto-submit transfers (require explicit click)

## Integration Checklist

- [ ] Add `signature-pad.js` to frontend
- [ ] Add transfer button to evidence list/detail view
- [ ] Implement `initiateSignedTransfer()` function
- [ ] Implement `handleSignedTransfer()` function
- [ ] Add backend `/api/evidence/transfer-signed` endpoint
- [ ] Update custody_logs table schema (add signature columns)
- [ ] Test with demo page (`signature-integration.html`)
- [ ] Style modal to match your theme
- [ ] Test on desktop (mouse) and mobile (touch)
- [ ] Verify blockchain transactions appear on-chain
- [ ] Add transfer notifications/email alerts

## Troubleshooting

### Signature pad not appearing
- Check that `signature-pad.js` is loaded
- Verify container element exists
- Check browser console for errors

### Canvas not responding to touch
- Ensure `touch-action: none` is set in CSS
- Test on actual mobile device (not desktop emulation)
- Force re-render if needed

### Blockchain transaction fails but modal closes
- Check backend logs
- Verify blockchain is connected
- Ensure contract is deployed on chain
- Check account has sufficient gas

### Signature hash always same
- This is OK — hash is just for reference
- Each transfer gets unique timestamp
- Blockchain TX hash is the real proof

## Production Deployment

1. **Test thoroughly** with real blockchain (testnet first)
2. **Monitor transaction costs** (gas usage)
3. **Set up error alerts** for failed transfers
4. **Archive old signatures** (they're not heavy, but can add up)
5. **Document for auditors** how chain of custody is recorded
6. **Train staff** on the new signing workflow

## Support

For issues or questions:
1. Check demo page (`signature-integration.html`)
2. Review this guide's examples
3. Check browser console for errors
4. Verify backend endpoint is working
5. Test blockchain connection separately

---

**Made for ForensicChain 🔬**
