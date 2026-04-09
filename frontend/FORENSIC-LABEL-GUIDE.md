# Forensic Label Component - Integration Guide

## Overview

The **Forensic Label** component is a reusable, professional UI element that displays evidence information with status indicators and custodian details. It mimics the appearance of a physical forensic evidence tag.

## Files

- **`forensic-label.js`** — JavaScript class for the component
- **`forensic-label-component.html`** — Full demo with all status states
- **`dashboard.html`** — Your existing dashboard (will be updated with integration examples)

## Quick Start

### 1. Include the Script

Add this line to your HTML `<head>` or before `</body>`:

```html
<script src="forensic-label.js"></script>
```

### 2. Basic Usage

```html
<!-- Container where labels will be rendered -->
<div id="labels-container"></div>

<script>
  const label = new ForensicLabel({
    id: 'EV-A7F2K9M1',
    status: 'available',
    custodian: 'Detective Mike Johnson',
    caseId: 'C-2026-001847',
    date: '2026-04-09'
  });

  document.getElementById('labels-container').appendChild(label.element);
</script>
```

## Status States

| Status | CSS Class | Color | Meaning |
|--------|-----------|-------|---------|
| `available` | `--badge--available` | **Green** | Evidence in custody |
| `pending_witness` | `--badge--pending` | **Yellow** | Awaiting witness attestation |
| `sealed` | `--badge--sealed` | **Red** | Court sealed/finalized |
| `tampered` | `--badge--tampered` | **Dark Red** | Integrity issue detected |
| `offline` | `--badge--offline` | **Gray** | Blockchain offline |

## API Reference

### Constructor

```javascript
const label = new ForensicLabel(evidenceData);
```

**Parameters:**
- `evidenceData` — Object with properties:
  - `id` (string) — Evidence ID (required)
  - `status` (string) — Status code (default: `'offline'`)
  - `custodian` (string) — Custodian name (default: `'Unknown Custodian'`)
  - `caseId` (string) — Case ID (default: `'N/A'`)
  - `date` (string, YYYY-MM-DD) — Date created (default: current date)

**Returns:** ForensicLabel instance with `.element` property

### Methods

#### `setStatus(newStatus)`
Dynamically update the status badge
```javascript
label.setStatus('sealed');
```

#### `setCustodian(custodianName)`
Update the custodian name and initials
```javascript
label.setCustodian('Court Officer Sarah Williams');
```

#### `label.element`
Access the DOM element
```javascript
document.body.appendChild(label.element);
```

### Static Methods

#### `ForensicLabel.create(evidenceData)`
Create and return a label element in one call
```javascript
const element = ForensicLabel.create({
  id: 'EV-B3X8Q2D4',
  status: 'pending_witness',
  custodian: 'Analyst Linda Chen'
});
```

#### `ForensicLabel.createMultiple(evidenceArray)`
Create multiple labels from an array
```javascript
const labels = ForensicLabel.createMultiple([
  { id: 'EV-1', status: 'available', custodian: 'Officer A' },
  { id: 'EV-2', status: 'sealed', custodian: 'Officer B' }
]);

labels.forEach(el => container.appendChild(el));
```

#### `ForensicLabel.injectStyles()`
Manually inject CSS (auto-called on script load)
```javascript
ForensicLabel.injectStyles();
```

## Integration with Dashboard

### Example: Display Evidence in Grid

```html
<div id="evidence-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px;">
  <!-- Labels will be inserted here -->
</div>

<script>
async function displayEvidence() {
  try {
    const response = await fetch('/api/evidence');
    const evidenceList = await response.json();

    const container = document.getElementById('evidence-grid');
    container.innerHTML = ''; // Clear existing

    evidenceList.forEach(evidence => {
      const label = new ForensicLabel({
        id: evidence.evidence_id,
        status: evidence.status, // 'available', 'pending_witness', etc.
        custodian: evidence.current_custodian_name,
        caseId: evidence.case_id,
        date: evidence.created_at.split('T')[0] // Extract date
      });

      container.appendChild(label.element);
    });
  } catch (error) {
    console.error('Failed to load evidence:', error);
  }
}

displayEvidence();
</script>
```

### Example: Dynamic Status Updates

```javascript
// When witness attestation completes
fetch('/api/seizure/attest', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ evidence_id: 'EV-A7F2K9M1', note: 'Witnessed' })
})
  .then(res => res.json())
  .then(result => {
    // Find and update the label
    const label = document.querySelector('[data-evidence-id="EV-A7F2K9M1"]');
    if (label) {
      const labelComponent = ForensicLabel.components.get('EV-A7F2K9M1');
      if (labelComponent) labelComponent.setStatus('sealed');
    }
  });
```

### Example: List with Click Handler

```html
<div id="evidence-list"></div>

<script>
async function renderEvidenceList() {
  const response = await fetch('/api/evidence');
  const evidenceList = await response.json();

  const container = document.getElementById('evidence-list');
  container.innerHTML = '';

  const componentMap = new Map();

  evidenceList.forEach(evidence => {
    const component = new ForensicLabel({
      id: evidence.evidence_id,
      status: evidence.status,
      custodian: evidence.current_custodian_name,
      caseId: evidence.case_id,
      date: evidence.created_at.split('T')[0]
    });

    // Store reference for later updates
    componentMap.set(evidence.evidence_id, component);

    // Add click handler
    component.element.style.cursor = 'pointer';
    component.element.addEventListener('click', () => {
      console.log('Clicked evidence:', evidence.evidence_id);
      // Navigate to detail view, etc.
      window.location.href = `/evidence/${evidence.evidence_id}`;
    });

    container.appendChild(component.element);
  });

  // Store map globally for later access
  window.forensicLabels = componentMap;
}

renderEvidenceList();
</script>
```

### Example: Timeline View

```html
<div id="evidence-timeline" style="border-left: 3px solid #e74c3c; padding-left: 20px;">
  <!-- Timeline events with labels -->
</div>

<script>
function renderTimeline(evidenceList) {
  const timeline = document.getElementById('evidence-timeline');
  timeline.innerHTML = '';

  evidenceList.forEach(evidence => {
    const timelineItem = document.createElement('div');
    timelineItem.style.marginBottom = '30px';
    timelineItem.style.position = 'relative';

    // Timeline dot
    const dot = document.createElement('div');
    dot.style.position = 'absolute';
    dot.style.left = '-26px';
    dot.style.width = '12px';
    dot.style.height = '12px';
    dot.style.borderRadius = '50%';
    dot.style.background = '#e74c3c';
    dot.style.top = '10px';

    timelineItem.appendChild(dot);

    // Label component
    const label = new ForensicLabel({
      id: evidence.evidence_id,
      status: evidence.status,
      custodian: evidence.current_custodian_name,
      caseId: evidence.case_id,
      date: evidence.created_at.split('T')[0]
    });

    timelineItem.appendChild(label.element);
    timeline.appendChild(timelineItem);
  });
}
</script>
```

## Styling Customization

### Override Colors

You can customize colors by modifying CSS variables:

```html
<style>
  :root {
    --forensic-primary: #1a1a2e;
    --forensic-border: #e74c3c;
    --forensic-bg-light: #f8f9fa;
    --status-green: #27ae60;
    --status-red: #e74c3c;
    --status-gray: #95a5a6;
    --status-yellow: #f39c12;
  }
</style>
```

### Custom Container Styling

```html
<style>
  .evidence-container {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 20px;
    padding: 20px;
  }
</style>
```

## Backend Integration

The component works best when your backend provides evidence data with these fields:

```json
{
  "evidence_id": "EV-A7F2K9M1",
  "status": "available",
  "current_custodian_name": "Detective Mike Johnson",
  "case_id": "C-2026-001847",
  "created_at": "2026-04-09T10:30:00Z",
  "file_hash": "a7d3f2k9m1...",
  "file_name": "suspects_photo.jpg"
}
```

## Real-World Example

Here's a complete example showing evidence with state management:

```html
<div id="app">
  <div id="filters" style="margin-bottom: 20px;">
    <button id="filter-all" class="active">All</button>
    <button id="filter-available">Available</button>
    <button id="filter-pending">Pending</button>
    <button id="filter-sealed">Sealed</button>
  </div>
  
  <div id="evidence-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px;">
    <!-- Labels render here -->
  </div>
</div>

<script>
let allEvidence = [];
let filteredEvidence = [];

async function loadEvidence() {
  const response = await fetch('/api/evidence');
  allEvidence = await response.json();
  renderLabels(allEvidence);
}

function renderLabels(evidence) {
  const container = document.getElementById('evidence-grid');
  container.innerHTML = '';

  evidence.forEach(ev => {
    const label = new ForensicLabel({
      id: ev.evidence_id,
      status: ev.status,
      custodian: ev.current_custodian_name,
      caseId: ev.case_id,
      date: ev.created_at.split('T')[0]
    });

    container.appendChild(label.element);
  });
}

// Filter buttons
document.getElementById('filter-all').addEventListener('click', () => {
  renderLabels(allEvidence);
});

document.getElementById('filter-available').addEventListener('click', () => {
  renderLabels(allEvidence.filter(e => e.status === 'available'));
});

document.getElementById('filter-pending').addEventListener('click', () => {
  renderLabels(allEvidence.filter(e => e.status === 'pending_witness'));
});

document.getElementById('filter-sealed').addEventListener('click', () => {
  renderLabels(allEvidence.filter(e => e.status === 'sealed'));
});

loadEvidence();
</script>
```

## Features

✅ **Professional Design** — Mimics physical evidence tags  
✅ **Responsive** — Works on desktop and mobile  
✅ **Dynamic Updates** — Change status and custodian with methods  
✅ **5 Status States** — Color-coded for quick visual identification  
✅ **Monospaced IDs** — Clear, readable evidence identifiers  
✅ **Hover Effects** — Subtle interactions for better UX  
✅ **No Dependencies** — Pure JavaScript, no frameworks required  
✅ **Accessibility** — Proper labels and semantic HTML  

## Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Mobile browsers (iOS Safari, Chrome Android)

## License

Part of the ForensicChain project
