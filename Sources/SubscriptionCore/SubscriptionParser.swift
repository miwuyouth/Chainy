// SubscriptionParser.swift
//
// Single entry point Chainy (or any other frontend) calls with raw
// subscription-URL response bodies: sniffs whether it's a Clash config
// (has a top-level `proxies:` key) or a v2ray-style base64/plain URI list,
// and routes to the matching parser. See ClashSubscriptionParser.swift and
// V2RaySubscriptionParser.swift for what each format actually looks like.

public enum SubscriptionParser {
    public static func parse(_ text: String) -> SubscriptionParseResult {
        if ClashSubscriptionParser.looksLikeClashYAML(text) {
            return ClashSubscriptionParser.parse(text)
        }
        return V2RaySubscriptionParser.parse(text)
    }
}
