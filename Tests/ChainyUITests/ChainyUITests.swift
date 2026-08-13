import XCTest

/// Drives the real Chainy.app via the accessibility tree (no screen capture --
/// XCUITest only ever inspects/screenshots the app's own window). Relies on
/// stable `sidebar.<id>` / `panel.<id>` / feature-specific identifiers set
/// across the Views (see each Edit's surrounding code), since visible text
/// ("Chain Builder", node names) isn't a safe/stable query key on its own.
final class ChainyUITests: XCTestCase {
    private var testDataDir: URL!

    override func setUpWithError() throws {
        continueAfterFailure = false
        testDataDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ChainyUITests-\(UUID().uuidString)", isDirectory: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: testDataDir)
    }

    /// Every launch gets its own throwaway `AppData.json` directory (see
    /// `ChainyApp.init`'s `CHAINY_UITEST_DATA_DIR` handling) so node/chain/
    /// subscription edits made here never touch the developer's real saved
    /// library, and `-autoConnectOnLaunch NO` keeps a launch from dialing a
    /// real node even if some other real profile had it enabled.
    private func launchApp() -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = ["-autoConnectOnLaunch", "NO"]
        app.launchEnvironment["CHAINY_UITEST_DATA_DIR"] = testDataDir.path
        app.launch()
        return app
    }

    /// `panel.<id>` lands on whatever container SwiftUI happens to pick for
    /// that screen (ScrollView for Overview, plain group elsewhere), so
    /// match by identifier across all element types rather than one type.
    private func panel(_ app: XCUIApplication, _ id: String) -> XCUIElement {
        app.descendants(matching: .any)["panel.\(id)"]
    }

    private func goTo(_ app: XCUIApplication, _ section: String) {
        let row = app.buttons["sidebar.\(section)"]
        XCTAssertTrue(row.waitForExistence(timeout: 5), "sidebar row \(section) never appeared")
        row.click()
        XCTAssertTrue(panel(app, section).waitForExistence(timeout: 5), "panel \(section) never appeared")
    }

    // MARK: - Navigation

    func testAppLaunchesToOverview() {
        let app = launchApp()
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: 5))
        XCTAssertTrue(panel(app, "overview").waitForExistence(timeout: 5))
    }

    func testSidebarNavigatesAllSections() {
        let app = launchApp()
        XCTAssertTrue(panel(app, "overview").waitForExistence(timeout: 5))

        for id in ["connections", "nodes", "chainBuilder", "logs", "settings", "overview"] {
            goTo(app, id)
        }
    }

    // MARK: - Nodes: add / edit / search

    func testAddNodeAppearsInLibrary() {
        let app = launchApp()
        goTo(app, "nodes")

        app.buttons["nodes.addButton"].click()
        let nameField = app.textFields["nodeEditor.name"]
        XCTAssertTrue(nameField.waitForExistence(timeout: 5))

        nameField.click()
        nameField.typeText("UITest Node")
        app.textFields["hopForm.host"].click()
        app.textFields["hopForm.host"].typeText("198.51.100.10")
        app.textFields["hopForm.port"].click()
        app.textFields["hopForm.port"].typeText("1080")

        let saveButton = app.buttons["nodeEditor.save"]
        XCTAssertTrue(saveButton.isEnabled, "Save should enable once host+port are valid")
        saveButton.click()

        XCTAssertTrue(app.staticTexts["UITest Node"].waitForExistence(timeout: 5), "new node should show up in the Nodes table")
    }

    func testEditingNodePrefillsExistingValues() {
        let app = launchApp()
        goTo(app, "nodes")

        app.buttons["nodes.addButton"].click()
        app.textFields["nodeEditor.name"].click()
        app.textFields["nodeEditor.name"].typeText("Edit Target")
        app.textFields["hopForm.host"].click()
        app.textFields["hopForm.host"].typeText("198.51.100.20")
        app.textFields["hopForm.port"].click()
        app.textFields["hopForm.port"].typeText("443")
        app.buttons["nodeEditor.save"].click()

        let row = app.staticTexts["Edit Target"]
        XCTAssertTrue(row.waitForExistence(timeout: 5))
        row.click()

        let nameField = app.textFields["nodeEditor.name"]
        XCTAssertTrue(nameField.waitForExistence(timeout: 5))
        XCTAssertEqual(nameField.value as? String, "Edit Target")
        app.buttons["nodeEditor.cancel"].click()
    }

    func testNodeSearchFiltersTable() {
        let app = launchApp()
        goTo(app, "nodes")

        for name in ["Alpha Node", "Beta Node"] {
            app.buttons["nodes.addButton"].click()
            app.textFields["nodeEditor.name"].click()
            app.textFields["nodeEditor.name"].typeText(name)
            app.textFields["hopForm.host"].click()
            app.textFields["hopForm.host"].typeText("198.51.100.30")
            app.textFields["hopForm.port"].click()
            app.textFields["hopForm.port"].typeText("1080")
            app.buttons["nodeEditor.save"].click()
        }

        XCTAssertTrue(app.staticTexts["Alpha Node"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Beta Node"].waitForExistence(timeout: 5))

        let search = app.textFields["nodes.searchField"]
        search.click()
        search.typeText("Alpha")

        XCTAssertTrue(app.staticTexts["Alpha Node"].waitForExistence(timeout: 5))
        // Give the filtered-out row a moment to actually disappear rather
        // than asserting on a stale snapshot from before the keystrokes.
        let betaGone = NSPredicate(format: "exists == 0")
        expectation(for: betaGone, evaluatedWith: app.staticTexts["Beta Node"])
        waitForExpectations(timeout: 5)
    }

    // MARK: - Chain Builder: build a chain from a library node

    func testBuildAndSaveChainFromLibraryNode() {
        let app = launchApp()
        goTo(app, "nodes")

        app.buttons["nodes.addButton"].click()
        app.textFields["nodeEditor.name"].click()
        app.textFields["nodeEditor.name"].typeText("UITest ChainNode")
        app.textFields["hopForm.host"].click()
        app.textFields["hopForm.host"].typeText("198.51.100.40")
        app.textFields["hopForm.port"].click()
        app.textFields["hopForm.port"].typeText("1080")
        app.buttons["nodeEditor.save"].click()
        XCTAssertTrue(app.staticTexts["UITest ChainNode"].waitForExistence(timeout: 5))

        goTo(app, "chainBuilder")

        // Empty-canvas state only, per ChainBuilderView.canvas.
        let addFirstHop = app.buttons["chainBuilder.addFirstHop"]
        XCTAssertTrue(addFirstHop.waitForExistence(timeout: 5))
        addFirstHop.click()

        let pickerRow = app.buttons["chainBuilder.nodePickerRow.UITest ChainNode"]
        XCTAssertTrue(pickerRow.waitForExistence(timeout: 5))
        pickerRow.click()

        // Chain name auto-fills from the staged hop's node name (see
        // ChainBuilderView.syncAutoName), so Save Chain should already be
        // enabled with no typing required.
        let saveChain = app.buttons["chainBuilder.saveChain"]
        XCTAssertTrue(saveChain.waitForExistence(timeout: 5))
        XCTAssertTrue(saveChain.isEnabled, "adding a hop should auto-fill the name and enable Save Chain")
        saveChain.click()

        XCTAssertTrue(app.staticTexts["Saved Chains"].waitForExistence(timeout: 5), "Saved Chains table should replace the empty state")
    }

    // MARK: - Connections: tab switching (no live traffic, so both start at 0)

    func testConnectionsTabsSwitchBetweenActiveAndClosed() {
        let app = launchApp()
        goTo(app, "connections")

        let active = app.radioButtons["connections.tab.active"].exists
            ? app.radioButtons["connections.tab.active"] : app.buttons["connections.tab.active"]
        let closed = app.radioButtons["connections.tab.closed"].exists
            ? app.radioButtons["connections.tab.closed"] : app.buttons["connections.tab.closed"]

        XCTAssertTrue(active.waitForExistence(timeout: 5))
        XCTAssertTrue(closed.waitForExistence(timeout: 5))

        closed.click()
        XCTAssertTrue(app.staticTexts["No closed connections yet"].waitForExistence(timeout: 5))

        active.click()
        XCTAssertTrue(app.staticTexts["No active connections"].waitForExistence(timeout: 5))
    }

    // MARK: - Logs: level filter (local @State only, no destructive action)

    func testLogsLevelFilterSwitchesWithoutCrashing() {
        let app = launchApp()
        goTo(app, "logs")

        for level in ["logs.level.all", "logs.level.info", "logs.level.warn", "logs.level.error"] {
            let segment = app.descendants(matching: .any)[level]
            XCTAssertTrue(segment.waitForExistence(timeout: 5), "\(level) segment never appeared")
            segment.click()
        }

        // Deliberately does not touch the "Clear" button in this panel --
        // it calls AppStore.clearLogs(), which wipes ProxyLog.shared's real
        // on-disk log file (not redirected by CHAINY_UITEST_DATA_DIR).
        XCTAssertTrue(panel(app, "logs").waitForExistence(timeout: 5))
    }
}
