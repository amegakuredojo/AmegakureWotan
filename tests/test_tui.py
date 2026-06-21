import pytest
from karasugakure.tui import KarasuTuiApp, GraphTreeWidget, LedgerIntegrityWidget, VaultEditor

@pytest.mark.asyncio
async def test_tui_layout_and_elements():
    """Verify that the Karasugakure TUI initializes correctly with all required tabs and sidebar components."""
    app = KarasuTuiApp()
    async with app.run_test() as pilot:
        # Verify app titles
        assert app.title == "KARASUGAKURE OSINT CONTROL PANEL"
        assert app.sub_title == "Tactical Intelligence & Forensic Graph Harness"
        
        # Verify sidebar components
        assert app.query_one("#sidebar") is not None
        assert app.query_one("#target-input") is not None
        assert app.query_one("#scan-mode") is not None
        assert app.query_one("#btn-scan") is not None
        
        # Verify layout tabs
        tabs = app.query_one("#tabs")
        assert tabs is not None
        
        # Verify Graph Explorer widget exists
        assert app.query_one("#graph-viewer", GraphTreeWidget) is not None
        
        # Verify Forensic Ledger widget exists
        assert app.query_one("#ledger-viewer", LedgerIntegrityWidget) is not None
        
        # Verify GPG Vault editor widget exists
        assert app.query_one("#vault-viewer", VaultEditor) is not None
        
        # Verify console log stream is present
        assert app.query_one("#console-logs") is not None
