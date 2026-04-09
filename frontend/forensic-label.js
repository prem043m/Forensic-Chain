/**
 * Forensic Label Component
 * A professional evidence tag component with status indicators and custodian information
 * 
 * Usage:
 *   const label = new ForensicLabel(evidenceData);
 *   document.getElementById('container').appendChild(label.element);
 * 
 * Or use static method:
 *   ForensicLabel.create(evidenceData); // returns HTML element
 */

class ForensicLabel {
  constructor(evidenceData) {
    this.data = {
      id: evidenceData.id || 'UNKNOWN',
      status: evidenceData.status || 'offline',
      custodian: evidenceData.custodian || 'Unknown Custodian',
      caseId: evidenceData.caseId || 'N/A',
      date: evidenceData.date || this._getCurrentDate(),
    };
    
    this.statusMap = {
      available: {
        class: 'forensic-label__badge--available',
        text: '✓ Available',
        description: 'Evidence in custody'
      },
      pending_witness: {
        class: 'forensic-label__badge--pending',
        text: '⧐ Pending Witness',
        description: 'Awaiting witness attestation'
      },
      sealed: {
        class: 'forensic-label__badge--sealed',
        text: '🔒 Court Sealed',
        description: 'Evidence court sealed'
      },
      tampered: {
        class: 'forensic-label__badge--tampered',
        text: '⚠ Tampered',
        description: 'Integrity issue detected'
      },
      offline: {
        class: 'forensic-label__badge--offline',
        text: '⊘ Offline',
        description: 'Blockchain offline'
      }
    };
    
    this.element = this._buildElement();
  }

  /**
   * Get current date in YYYY-MM-DD format
   */
  _getCurrentDate() {
    const now = new Date();
    return now.toISOString().split('T')[0];
  }

  /**
   * Extract initials from custodian name
   */
  _getInitials(name) {
    return name
      .split(' ')
      .map(part => part[0])
      .join('')
      .toUpperCase()
      .slice(0, 2);
  }

  /**
   * Generate a simple barcode-like pattern
   */
  _buildBarcodeElement() {
    const barcode = document.createElement('div');
    barcode.className = 'forensic-label__barcode';
    return barcode;
  }

  /**
   * Build the main element
   */
  _buildElement() {
    const container = document.createElement('div');
    container.className = 'forensic-label';
    container.dataset.evidenceId = this.data.id;
    container.dataset.status = this.data.status;

    // Header
    const header = document.createElement('div');
    header.className = 'forensic-label__header';
    
    const title = document.createElement('span');
    title.className = 'forensic-label__title';
    title.textContent = 'Forensic Evidence';
    
    header.appendChild(title);
    header.appendChild(this._buildBarcodeElement());
    container.appendChild(header);

    // Content
    const content = document.createElement('div');
    content.className = 'forensic-label__content';

    // ID Section
    content.appendChild(this._buildIdSection());

    // Status Section
    content.appendChild(this._buildStatusSection());

    // Custodian Section
    content.appendChild(this._buildCustodianSection());

    container.appendChild(content);

    // Footer
    container.appendChild(this._buildFooter());

    return container;
  }

  /**
   * Build ID section
   */
  _buildIdSection() {
    const section = document.createElement('div');
    section.className = 'forensic-label__id-section';

    const label = document.createElement('label');
    label.className = 'forensic-label__id-label';
    label.textContent = 'Evidence ID';

    const id = document.createElement('div');
    id.className = 'forensic-label__id';
    id.textContent = this.data.id;
    id.title = `Evidence ID: ${this.data.id}`;

    section.appendChild(label);
    section.appendChild(id);
    return section;
  }

  /**
   * Build status section
   */
  _buildStatusSection() {
    const section = document.createElement('div');
    section.className = 'forensic-label__status-section';

    const label = document.createElement('label');
    label.className = 'forensic-label__status-label';
    label.textContent = 'Status';

    const statusInfo = this.statusMap[this.data.status] || this.statusMap.offline;
    const badge = document.createElement('span');
    badge.className = `forensic-label__badge ${statusInfo.class}`;
    badge.textContent = statusInfo.text;
    badge.title = statusInfo.description;

    section.appendChild(label);
    section.appendChild(badge);
    return section;
  }

  /**
   * Build custodian section
   */
  _buildCustodianSection() {
    const section = document.createElement('div');
    section.className = 'forensic-label__custodian-section';

    const label = document.createElement('label');
    label.className = 'forensic-label__custodian-label';
    label.textContent = 'Current Custodian';

    const custodian = document.createElement('div');
    custodian.className = 'forensic-label__custodian';

    const icon = document.createElement('div');
    icon.className = 'forensic-label__custodian-icon';
    icon.textContent = this._getInitials(this.data.custodian);
    icon.title = this.data.custodian;

    const name = document.createElement('div');
    name.className = 'forensic-label__custodian-name';
    name.textContent = this.data.custodian;
    name.title = this.data.custodian;

    custodian.appendChild(icon);
    custodian.appendChild(name);

    section.appendChild(label);
    section.appendChild(custodian);
    return section;
  }

  /**
   * Build footer
   */
  _buildFooter() {
    const footer = document.createElement('div');
    footer.className = 'forensic-label__footer';

    const caseInfo = document.createElement('span');
    caseInfo.textContent = `Case ID: ${this.data.caseId}`;

    const timestamp = document.createElement('span');
    timestamp.className = 'forensic-label__timestamp';
    timestamp.textContent = this.data.date;

    footer.appendChild(caseInfo);
    footer.appendChild(timestamp);
    return footer;
  }

  /**
   * Update status dynamically
   */
  setStatus(newStatus) {
    if (this.statusMap[newStatus]) {
      this.data.status = newStatus;
      const statusSection = this.element.querySelector('.forensic-label__status-section');
      const statusInfo = this.statusMap[newStatus];
      
      const badge = statusSection.querySelector('.forensic-label__badge');
      badge.className = `forensic-label__badge ${statusInfo.class}`;
      badge.textContent = statusInfo.text;
      badge.title = statusInfo.description;
      
      this.element.dataset.status = newStatus;
    }
  }

  /**
   * Update custodian dynamically
   */
  setCustodian(custodianName) {
    this.data.custodian = custodianName;
    
    const icon = this.element.querySelector('.forensic-label__custodian-icon');
    icon.textContent = this._getInitials(custodianName);
    icon.title = custodianName;
    
    const name = this.element.querySelector('.forensic-label__custodian-name');
    name.textContent = custodianName;
    name.title = custodianName;
  }

  /**
   * Static method to create and return element
   */
  static create(evidenceData) {
    const label = new ForensicLabel(evidenceData);
    return label.element;
  }

  /**
   * Static method to create multiple labels from array
   */
  static createMultiple(evidenceArray) {
    return evidenceArray.map(data => new ForensicLabel(data).element);
  }

  /**
   * Static method to inject CSS into document
   */
  static injectStyles() {
    if (document.getElementById('forensic-label-styles')) {
      return; // Already injected
    }

    const styles = `
      .forensic-label {
        background: white;
        border: 3px solid #e74c3c;
        border-radius: 4px;
        padding: 0;
        box-shadow: 
          0 4px 6px rgba(0, 0, 0, 0.1),
          inset 0 1px 3px rgba(255, 255, 255, 0.5);
        max-width: 100%;
        font-family: 'Courier New', monospace;
        transition: transform 0.2s ease, box-shadow 0.2s ease;
      }

      .forensic-label:hover {
        transform: translateY(-2px);
        box-shadow: 
          0 8px 12px rgba(0, 0, 0, 0.15),
          inset 0 1px 3px rgba(255, 255, 255, 0.5);
      }

      .forensic-label__header {
        background: #1a1a2e;
        color: white;
        padding: 12px 16px;
        border-bottom: 2px solid #e74c3c;
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 12px;
      }

      .forensic-label__title {
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #e74c3c;
      }

      .forensic-label__barcode {
        width: 40px;
        height: 20px;
        background: repeating-linear-gradient(
          90deg,
          #333 0, #333 2px,
          white 2px, white 4px,
          #333 4px, #333 5px,
          white 5px, white 9px
        );
        border: 1px solid #333;
        border-radius: 2px;
      }

      .forensic-label__content {
        padding: 16px 16px;
      }

      .forensic-label__id-section {
        margin-bottom: 14px;
      }

      .forensic-label__id-label {
        display: block;
        font-size: 10px;
        font-weight: 600;
        text-transform: uppercase;
        color: #666;
        letter-spacing: 0.8px;
        margin-bottom: 4px;
      }

      .forensic-label__id {
        font-family: 'Courier New', monospace;
        font-size: 14px;
        font-weight: 700;
        color: #1a1a2e;
        background: #f8f9fa;
        padding: 8px 10px;
        border-radius: 3px;
        border: 1px solid #ddd;
        word-break: break-all;
        letter-spacing: 1px;
      }

      .forensic-label__status-section {
        margin-bottom: 14px;
      }

      .forensic-label__status-label {
        display: block;
        font-size: 10px;
        font-weight: 600;
        text-transform: uppercase;
        color: #666;
        letter-spacing: 0.8px;
        margin-bottom: 6px;
      }

      .forensic-label__badge {
        display: inline-block;
        padding: 6px 12px;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        color: white;
        transition: all 0.2s ease;
      }

      .forensic-label__badge--available {
        background: #27ae60;
        box-shadow: 0 2px 8px rgba(39, 174, 96, 0.3);
      }

      .forensic-label__badge--pending {
        background: #f39c12;
        box-shadow: 0 2px 8px rgba(243, 156, 18, 0.3);
      }

      .forensic-label__badge--sealed {
        background: #e74c3c;
        box-shadow: 0 2px 8px rgba(231, 76, 60, 0.3);
      }

      .forensic-label__badge--tampered {
        background: #c0392b;
        box-shadow: 0 2px 8px rgba(192, 57, 43, 0.3);
      }

      .forensic-label__badge--offline {
        background: #95a5a6;
        box-shadow: 0 2px 8px rgba(149, 165, 166, 0.3);
      }

      .forensic-label__custodian-section {
        padding-top: 12px;
        border-top: 1px dashed #ddd;
      }

      .forensic-label__custodian-label {
        display: block;
        font-size: 10px;
        font-weight: 600;
        text-transform: uppercase;
        color: #666;
        letter-spacing: 0.8px;
        margin-bottom: 6px;
      }

      .forensic-label__custodian {
        font-size: 12px;
        font-weight: 600;
        color: #1a1a2e;
        padding: 6px 8px;
        background: #f8f9fa;
        border-radius: 3px;
        border-left: 3px solid #e74c3c;
        display: flex;
        align-items: center;
        gap: 8px;
      }

      .forensic-label__custodian-icon {
        width: 16px;
        height: 16px;
        background: #1a1a2e;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        font-size: 9px;
        font-weight: bold;
      }

      .forensic-label__custodian-name {
        flex: 1;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }

      .forensic-label__footer {
        background: #f8f9fa;
        padding: 8px 16px;
        border-top: 1px solid #ddd;
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 9px;
        color: #999;
        text-transform: uppercase;
        letter-spacing: 0.5px;
      }

      .forensic-label__timestamp {
        font-family: 'Courier New', monospace;
        font-size: 9px;
      }

      @media (max-width: 600px) {
        .forensic-label__header {
          flex-direction: column;
          align-items: flex-start;
          gap: 8px;
        }

        .forensic-label {
          border-width: 2px;
        }
      }
    `;

    const styleElement = document.createElement('style');
    styleElement.id = 'forensic-label-styles';
    styleElement.textContent = styles;
    document.head.appendChild(styleElement);
  }
}

// Auto-inject styles when script loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => ForensicLabel.injectStyles());
} else {
  ForensicLabel.injectStyles();
}
