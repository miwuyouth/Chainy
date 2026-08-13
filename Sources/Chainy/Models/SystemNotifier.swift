// SystemNotifier.swift
//
// Thin wrapper around `UNUserNotificationCenter` gated by the "System
// Notifications" toggle in Settings (`enabledDefaultsKey` in
// `UserDefaults`, bound there via `@AppStorage`). Callers don't need to
// check the toggle or authorization status themselves -- `post` no-ops
// unless both are satisfied.

import Foundation
import UserNotifications

enum SystemNotifier {
    static let enabledDefaultsKey = "systemNotificationsEnabled"

    /// Without a delegate installed, macOS silently drops local
    /// notifications fired while Chainy is the frontmost app -- delivered
    /// to nothing, no banner, no sound -- which is why "Send Test" can
    /// look like it does nothing even with permission already granted.
    /// `ChainyApp.init()` calls this once at launch; `UNUserNotificationCenter
    /// .delegate` is `weak`, so `Delegate.shared` also keeps it alive.
    static func installDelegate() {
        UNUserNotificationCenter.current().delegate = Delegate.shared
    }

    private final class Delegate: NSObject, UNUserNotificationCenterDelegate {
        static let shared = Delegate()

        func userNotificationCenter(
            _ center: UNUserNotificationCenter,
            willPresent notification: UNNotification,
            withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
        ) {
            completionHandler([.banner, .sound])
        }
    }

    /// Triggers the system permission prompt right when the toggle is
    /// switched on, rather than waiting for the first `post` -- so the user
    /// sees the prompt as a direct result of their action instead of an
    /// unexplained dialog the next time the proxy happens to connect.
    /// No-ops once the user has already answered (allowed or denied).
    static func requestAuthorizationIfNeeded() {
        let center = UNUserNotificationCenter.current()
        center.getNotificationSettings { settings in
            guard settings.authorizationStatus == .notDetermined else { return }
            center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
        }
    }

    /// Posts an immediate local notification, unless the Settings toggle is
    /// off or the user never granted permission.
    static func post(title: String, body: String) {
        guard UserDefaults.standard.bool(forKey: enabledDefaultsKey) else { return }
        let center = UNUserNotificationCenter.current()
        center.getNotificationSettings { settings in
            guard settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional else { return }
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            content.sound = .default
            center.add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
        }
    }

    enum TestResult {
        case sent
        case denied
        case failed
    }

    /// Unlike `post`, ignores the Settings toggle -- this is an explicit,
    /// user-initiated "Send Test" tap rather than a background event, so it
    /// always attempts, then reports back whether it actually landed (the
    /// caller shows that as inline feedback next to the toggle).
    static func sendTest(completion: @escaping (TestResult) -> Void) {
        let center = UNUserNotificationCenter.current()
        center.getNotificationSettings { settings in
            switch settings.authorizationStatus {
            case .authorized, .provisional:
                deliverTest(center: center, completion: completion)
            case .notDetermined:
                center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
                    guard granted else {
                        DispatchQueue.main.async { completion(.denied) }
                        return
                    }
                    deliverTest(center: center, completion: completion)
                }
            default:
                DispatchQueue.main.async { completion(.denied) }
            }
        }
    }

    private static func deliverTest(center: UNUserNotificationCenter, completion: @escaping (TestResult) -> Void) {
        let content = UNMutableNotificationContent()
        content.title = "Chainy"
        content.body = "System notifications are working."
        content.sound = .default
        center.add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)) { error in
            DispatchQueue.main.async { completion(error == nil ? .sent : .failed) }
        }
    }
}
